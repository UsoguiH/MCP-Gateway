import { useEffect, useState } from "react";
import { Eye, EyeOff, KeyRound, ShieldCheck, LogOut } from "lucide-react";
import { login, verifyMfa, quickLogin, changePassword, authInfo, type User } from "@/api";

// Exact styling ported from Login-page.txt (green RTL, glass inputs, entrance
// animation), centered with no side panel, wired to the real 2FA flow.
const ANIM = `
@keyframes elementIn { from { opacity: 0; transform: translateY(24px); } to { opacity: 1; transform: translateY(0); } }
.animate-element { animation: elementIn 0.9s cubic-bezier(0.16, 1, 0.3, 1) both; }
`;

// Bilingual copy — the login was Arabic-only while the rest of the app is English,
// so a non-Arabic operator couldn't read it (and vice-versa). Toggle persists.
const AR_FONT = '"IBM Plex Sans Arabic", Inter, sans-serif';
type Lang = "ar" | "en";
const STR: Record<Lang, Record<string, string>> = {
  ar: {
    hello: "مرحباً",
    credsSub: "الوصول إلى حسابك ومتابعة رحلتك معنا",
    otpSub: "أدخل الرمز المكوّن من 6 أرقام من تطبيق المصادقة",
    username: "اسم المستخدم",
    usernamePh: "أدخل اسم المستخدم",
    password: "كلمة المرور",
    passwordPh: "أدخل كلمة المرور",
    forgot: "إعادة تعيين كلمة المرور",
    forgotNote: "لإعادة تعيين كلمة المرور تواصل مع مسؤول النظام.",
    signIn: "تسجيل الدخول",
    signingIn: "جارٍ تسجيل الدخول…",
    needCreds: "أدخل اسم المستخدم وكلمة المرور.",
    badCreds: "اسم المستخدم أو كلمة المرور غير صحيحة.",
    otpLabel: "رمز المصادقة",
    needOtp: "أدخل الرمز المكوّن من 6 أرقام.",
    badOtp: "رمز غير صحيح",
    back: "رجوع",
    working: "جارٍ…",
    createAccount: "إنشاء حساب",
    createNote: "الحسابات تُنشأ عبر مسؤول النظام.",
    quick: "الدخول السريع (وضع المطوّر)",
    quickErr: "الدخول السريع غير متاح",
  },
  en: {
    hello: "Welcome",
    credsSub: "Sign in to your account to continue.",
    otpSub: "Enter the 6-digit code from your authenticator app.",
    username: "Username",
    usernamePh: "Enter your username",
    password: "Password",
    passwordPh: "Enter your password",
    forgot: "Reset password",
    forgotNote: "To reset your password, contact your system administrator.",
    signIn: "Sign in",
    signingIn: "Signing in…",
    needCreds: "Enter your username and password.",
    badCreds: "Incorrect username or password.",
    otpLabel: "Authentication code",
    needOtp: "Enter the 6-digit code.",
    badOtp: "Incorrect code",
    back: "Back",
    working: "Working…",
    createAccount: "Create account",
    createNote: "Accounts are created by your system administrator.",
    quick: "Quick sign-in (developer mode)",
    quickErr: "Quick sign-in unavailable",
  },
};

function GlassInputWrapper({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-2xl border border-gray-200 bg-gray-900/5 backdrop-blur-sm transition-colors focus-within:border-green-400/70 focus-within:bg-green-500/10">
      {children}
    </div>
  );
}

export function LoginScreen({ onDone }: { onDone: (u: User) => void }) {
  const [step, setStep] = useState<"creds" | "otp">("creds");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [otp, setOtp] = useState("");
  const [mfaTicket, setMfaTicket] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [quick, setQuick] = useState(false);
  const [err, setErr] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [lang, setLang] = useState<Lang>(() => (localStorage.getItem("mcp_lang") as Lang) || "ar");

  const t = (k: string) => STR[lang][k];
  const dir = lang === "ar" ? "rtl" : "ltr";
  const align = lang === "ar" ? "text-right" : "text-left";
  const toggleLang = () => setLang((l) => { const n = l === "ar" ? "en" : "ar"; localStorage.setItem("mcp_lang", n); return n; });

  useEffect(() => { authInfo().then((i) => { setQuick(!!i.dev_quick_login); }); }, []);

  // Layer 1: verify username + password. A wrong password stops here — we only
  // advance to the MFA step when the password is confirmed.
  const onSignIn = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username || !password) { setErr(t("needCreds")); return; }
    setErr(""); setBusy(true);
    try {
      const res = await login(username, password);
      if ("user" in res) { onDone(res.user); }             // MFA disabled — done
      else { setMfaTicket(res.mfaTicket); setStep("otp"); } // advance to layer 2
    } catch (e: any) { setErr(e.message || t("badCreds")); }
    finally { setBusy(false); }
  };
  // Layer 2: verify the TOTP code with the ticket from layer 1.
  const submit = async () => {
    if (otp.trim().length < 6) { setErr(t("needOtp")); return; }
    setErr(""); setBusy(true);
    try { onDone(await verifyMfa(mfaTicket, otp)); }
    catch (e: any) {
      setErr(e.message || t("badOtp"));
      if (/expired|expire|أدخل اسم/.test(e.message || "")) { setStep("creds"); setOtp(""); setMfaTicket(""); }
    }
    finally { setBusy(false); }
  };
  const enterNow = async () => {
    setErr(""); setBusy(true);
    try { onDone(await quickLogin()); }
    catch (e: any) { setErr(e.message || t("quickErr")); }
    finally { setBusy(false); }
  };

  return (
    <div dir={dir} className={`relative min-h-screen w-screen flex items-center justify-center bg-white ${align}`}
         style={{ fontFamily: lang === "ar" ? AR_FONT : "Inter, sans-serif" }}>
      <style>{ANIM}</style>
      {/* Language toggle — top corner, opposite the reading direction's start */}
      <button onClick={toggleLang} type="button"
        className="absolute top-5 right-5 text-sm text-gray-500 hover:text-gray-900 border border-gray-200 rounded-full px-4 py-1.5 hover:bg-gray-900/5 transition-colors"
        style={{ fontFamily: lang === "ar" ? "Inter, sans-serif" : AR_FONT }}>
        {lang === "ar" ? "English" : "العربية"}
      </button>
      <section className="w-full max-w-md p-8">
        <div className="flex flex-col gap-6">
          <h1 className="animate-element text-4xl md:text-5xl font-light text-gray-900 tracking-tighter leading-tight" style={{ animationDelay: "0.1s" }}>
            {t("hello")}
          </h1>
          <p className="animate-element text-gray-500" style={{ animationDelay: "0.2s" }}>
            {step === "creds" ? t("credsSub") : t("otpSub")}
          </p>

          {step === "creds" ? (
            <form className="space-y-5" onSubmit={onSignIn}>
              <div className="animate-element" style={{ animationDelay: "0.3s" }}>
                <label className="text-sm font-medium text-gray-500">{t("username")}</label>
                <GlassInputWrapper>
                  <input
                    autoFocus
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    type="text"
                    placeholder={t("usernamePh")}
                    className={`w-full bg-transparent text-sm p-4 rounded-2xl focus:outline-none ${align}`}
                  />
                </GlassInputWrapper>
              </div>

              <div className="animate-element" style={{ animationDelay: "0.4s" }}>
                <label className="text-sm font-medium text-gray-500">{t("password")}</label>
                <GlassInputWrapper>
                  <div className="relative">
                    <input
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      type={showPassword ? "text" : "password"}
                      placeholder={t("passwordPh")}
                      className={`w-full bg-transparent text-sm p-4 ${lang === "ar" ? "pl-12" : "pr-12"} rounded-2xl focus:outline-none ${align}`}
                    />
                    <button type="button" onClick={() => setShowPassword(!showPassword)} className={`absolute inset-y-0 ${lang === "ar" ? "left-3" : "right-3"} flex items-center`}>
                      {showPassword ? <EyeOff className="w-5 h-5 text-gray-500 hover:text-gray-900 transition-colors" /> : <Eye className="w-5 h-5 text-gray-500 hover:text-gray-900 transition-colors" />}
                    </button>
                  </div>
                </GlassInputWrapper>
              </div>

              <div className={`animate-element flex items-center ${lang === "ar" ? "justify-start" : "justify-end"} text-sm`} style={{ animationDelay: "0.5s" }}>
                <a href="#" onClick={(e) => { e.preventDefault(); setNote(t("forgotNote")); }} className="hover:underline text-green-500 transition-colors">
                  {t("forgot")}
                </a>
              </div>

              {err && <p className="animate-element text-sm text-red-500">{err}</p>}
              {note && <p className="animate-element text-sm text-gray-500">{note}</p>}

              <button type="submit" disabled={busy} className="animate-element w-full rounded-2xl bg-green-600 py-4 font-medium text-white hover:bg-green-700 transition-colors disabled:opacity-50" style={{ animationDelay: "0.6s" }}>
                {busy ? t("signingIn") : t("signIn")}
              </button>
            </form>
          ) : (
            <div className="flex flex-col gap-5">
              <div className="animate-element flex items-center gap-2 text-sm text-gray-600 bg-gray-900/5 border border-gray-200 rounded-2xl p-4" style={{ animationDelay: "0.2s" }}>
                <ShieldCheck size={16} className="text-green-600" /> {username}
              </div>
              <div className="animate-element" style={{ animationDelay: "0.3s" }}>
                <label className="text-sm font-medium text-gray-500">{t("otpLabel")}</label>
                <GlassInputWrapper>
                  <input
                    autoFocus inputMode="numeric" maxLength={6}
                    value={otp}
                    onChange={(e) => setOtp(e.target.value.replace(/\D/g, ""))}
                    onKeyDown={(e) => e.key === "Enter" && submit()}
                    placeholder="000000"
                    className="w-full bg-transparent text-lg p-4 rounded-2xl focus:outline-none text-center tracking-[0.4em]"
                  />
                </GlassInputWrapper>
              </div>
              {err && <span className="text-sm text-red-500">{err}</span>}
              <div className="flex gap-3">
                <button onClick={() => { setStep("creds"); setErr(""); setOtp(""); }} className="rounded-2xl border border-gray-200 px-5 py-4 text-sm text-gray-700 hover:bg-gray-900/5">{t("back")}</button>
                <button onClick={submit} disabled={busy} className="flex-1 rounded-2xl bg-green-600 py-4 font-medium text-white hover:bg-green-700 disabled:opacity-50">{busy ? t("working") : t("signIn")}</button>
              </div>
            </div>
          )}

          {step === "creds" && (
            <p className="animate-element text-center text-sm" style={{ animationDelay: "0.7s" }}>
              <a href="#" onClick={(e) => { e.preventDefault(); setNote(t("createNote")); }} className="text-green-500 hover:underline transition-colors font-medium">
                {t("createAccount")}
              </a>
            </p>
          )}

          {step === "creds" && quick && (
            <p className="animate-element text-center" style={{ animationDelay: "0.8s" }}>
              <a href="#" onClick={(e) => { e.preventDefault(); enterNow(); }} className="text-xs text-gray-400 hover:text-green-600 transition-colors">
                {t("quick")}
              </a>
            </p>
          )}
        </div>
      </section>
    </div>
  );
}

export function ChangePasswordScreen({ onDone, onLogout }: { onDone: () => void; onLogout: () => void }) {
  const [oldPw, setOldPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    setErr("");
    if (newPw !== confirm) { setErr("كلمتا المرور غير متطابقتين."); return; }
    setBusy(true);
    try { await changePassword(oldPw, newPw); onDone(); }
    catch (e: any) { setErr(e.message || "تعذّر التغيير"); }
    finally { setBusy(false); }
  };
  return (
    <div dir="rtl" className="min-h-screen w-screen flex items-center justify-center bg-white text-right" style={{ fontFamily: "Inter, sans-serif" }}>
      <div className="w-[400px] p-8 flex flex-col gap-5">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-green-600 flex items-center justify-center shrink-0"><KeyRound size={18} className="text-white" /></div>
          <div className="flex flex-col">
            <span className="text-lg font-light text-gray-900">تعيين كلمة مرور جديدة</span>
            <span className="text-xs text-gray-500">يجب تغيير كلمة المرور قبل المتابعة.</span>
          </div>
        </div>
        {[["كلمة المرور الحالية", oldPw, setOldPw], ["كلمة المرور الجديدة", newPw, setNewPw], ["تأكيد كلمة المرور", confirm, setConfirm]].map(([label, val, set]: any, i) => (
          <div key={i}>
            <label className="text-sm font-medium text-gray-500">{label}</label>
            <GlassInputWrapper><input type="password" value={val} onChange={(e) => set(e.target.value)} onKeyDown={(e) => e.key === "Enter" && submit()}
              className="w-full bg-transparent text-sm p-4 rounded-2xl focus:outline-none text-right" /></GlassInputWrapper>
          </div>
        ))}
        {err && <span className="text-sm text-red-500">{err}</span>}
        <div className="flex gap-2 justify-end">
          <button onClick={onLogout} className="text-sm text-gray-700 px-4 py-3 rounded-2xl border border-gray-200 hover:bg-gray-900/5 flex items-center gap-1"><LogOut size={13} /> خروج</button>
          <button onClick={submit} disabled={busy} className="text-sm text-white px-5 py-3 rounded-2xl bg-green-600 hover:bg-green-700 disabled:opacity-50">{busy ? "جارٍ…" : "تحديث"}</button>
        </div>
      </div>
    </div>
  );
}

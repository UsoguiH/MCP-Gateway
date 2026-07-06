import { useEffect, useState } from "react";
import { Eye, EyeOff, KeyRound, ShieldCheck, LogOut } from "lucide-react";
import { login, quickLogin, changePassword, authInfo, type User } from "@/api";

// Exact styling ported from Login-page.txt (green RTL, glass inputs, entrance
// animation), centered with no side panel, wired to the real 2FA flow.
const ANIM = `
@keyframes elementIn { from { opacity: 0; transform: translateY(24px); } to { opacity: 1; transform: translateY(0); } }
.animate-element { animation: elementIn 0.9s cubic-bezier(0.16, 1, 0.3, 1) both; }
`;

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
  const [showPassword, setShowPassword] = useState(false);
  const [mfa, setMfa] = useState(true);
  const [quick, setQuick] = useState(false);
  const [err, setErr] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => { authInfo().then((i) => { setMfa(i.mfa_required !== false); setQuick(!!i.dev_quick_login); }); }, []);

  const submit = async () => {
    setErr(""); setBusy(true);
    try { onDone(await login(username, password, otp)); }
    catch (e: any) { setErr(e.message || "تعذّر تسجيل الدخول"); }
    finally { setBusy(false); }
  };
  const onSignIn = (e: React.FormEvent) => {
    e.preventDefault();
    if (!username || !password) { setErr("أدخل اسم المستخدم وكلمة المرور."); return; }
    if (mfa) { setErr(""); setStep("otp"); } else submit();
  };
  const enterNow = async () => {
    setErr(""); setBusy(true);
    try { onDone(await quickLogin()); }
    catch (e: any) { setErr(e.message || "الدخول السريع غير متاح"); }
    finally { setBusy(false); }
  };

  return (
    <div dir="rtl" className="relative min-h-screen w-screen flex items-center justify-center bg-white text-right">
      <style>{ANIM}</style>
      <section className="w-full max-w-md p-8">
        <div className="flex flex-col gap-6">
          <h1 className="animate-element text-4xl md:text-5xl font-light text-gray-900 tracking-tighter leading-tight" style={{ animationDelay: "0.1s" }}>
            مرحباً
          </h1>
          <p className="animate-element text-gray-500" style={{ animationDelay: "0.2s" }}>
            {step === "creds" ? "الوصول إلى حسابك ومتابعة رحلتك معنا" : "أدخل الرمز المكوّن من 6 أرقام من تطبيق المصادقة"}
          </p>

          {step === "creds" ? (
            <form className="space-y-5" onSubmit={onSignIn}>
              <div className="animate-element" style={{ animationDelay: "0.3s" }}>
                <label className="text-sm font-medium text-gray-500">البريد الإلكتروني</label>
                <GlassInputWrapper>
                  <input
                    autoFocus
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    type="text"
                    placeholder="أدخل بريدك الإلكتروني"
                    className="w-full bg-transparent text-sm p-4 rounded-2xl focus:outline-none text-right"
                  />
                </GlassInputWrapper>
              </div>

              <div className="animate-element" style={{ animationDelay: "0.4s" }}>
                <label className="text-sm font-medium text-gray-500">كلمة المرور</label>
                <GlassInputWrapper>
                  <div className="relative">
                    <input
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      type={showPassword ? "text" : "password"}
                      placeholder="أدخل كلمة المرور"
                      className="w-full bg-transparent text-sm p-4 pl-12 rounded-2xl focus:outline-none text-right"
                    />
                    <button type="button" onClick={() => setShowPassword(!showPassword)} className="absolute inset-y-0 left-3 flex items-center">
                      {showPassword ? <EyeOff className="w-5 h-5 text-gray-500 hover:text-gray-900 transition-colors" /> : <Eye className="w-5 h-5 text-gray-500 hover:text-gray-900 transition-colors" />}
                    </button>
                  </div>
                </GlassInputWrapper>
              </div>

              <div className="animate-element flex items-center justify-end text-sm" style={{ animationDelay: "0.5s" }}>
                <a href="#" onClick={(e) => { e.preventDefault(); setNote("لإعادة تعيين كلمة المرور تواصل مع مسؤول النظام."); }} className="hover:underline text-green-500 transition-colors">
                  إعادة تعيين كلمة المرور
                </a>
              </div>

              {err && <p className="animate-element text-sm text-red-500">{err}</p>}
              {note && <p className="animate-element text-sm text-gray-500">{note}</p>}

              <button type="submit" disabled={busy} className="animate-element w-full rounded-2xl bg-green-600 py-4 font-medium text-white hover:bg-green-700 transition-colors disabled:opacity-50" style={{ animationDelay: "0.6s" }}>
                {busy ? "جارٍ تسجيل الدخول…" : "تسجيل الدخول"}
              </button>
            </form>
          ) : (
            <div className="flex flex-col gap-5">
              <div className="animate-element flex items-center gap-2 text-sm text-gray-600 bg-gray-900/5 border border-gray-200 rounded-2xl p-4" style={{ animationDelay: "0.2s" }}>
                <ShieldCheck size={16} className="text-green-600" /> {username}
              </div>
              <div className="animate-element" style={{ animationDelay: "0.3s" }}>
                <label className="text-sm font-medium text-gray-500">رمز المصادقة</label>
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
                <button onClick={() => { setStep("creds"); setErr(""); setOtp(""); }} className="rounded-2xl border border-gray-200 px-5 py-4 text-sm text-gray-700 hover:bg-gray-900/5">رجوع</button>
                <button onClick={submit} disabled={busy} className="flex-1 rounded-2xl bg-green-600 py-4 font-medium text-white hover:bg-green-700 disabled:opacity-50">{busy ? "جارٍ…" : "تسجيل الدخول"}</button>
              </div>
            </div>
          )}

          {step === "creds" && (
            <p className="animate-element text-center text-sm" style={{ animationDelay: "0.7s" }}>
              <a href="#" onClick={(e) => { e.preventDefault(); setNote("الحسابات تُنشأ عبر مسؤول النظام."); }} className="text-green-500 hover:underline transition-colors font-medium">
                إنشاء حساب
              </a>
            </p>
          )}

          {step === "creds" && quick && (
            <p className="animate-element text-center" style={{ animationDelay: "0.8s" }}>
              <a href="#" onClick={(e) => { e.preventDefault(); enterNow(); }} className="text-xs text-gray-400 hover:text-green-600 transition-colors">
                الدخول السريع (وضع المطوّر)
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

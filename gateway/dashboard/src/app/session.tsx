// Session lifetime guard (Phase 2, A12).
//
// The console used to hold one fixed-lifetime token and simply die when it ran out — an
// admin mid-approval would suddenly find themselves on the login screen, with no warning,
// no countdown, and no way to stay signed in. There was no TTL or idle setting anywhere.
//
// Now:
//   * While the operator is ACTIVE, the session renews silently in the background. The
//     configured TTL therefore behaves as an IDLE timeout — you only lapse if you stop.
//   * When they are idle and expiry approaches, a modal counts down and offers to extend.
//   * The server's absolute cap still forces a real re-authentication eventually; when it
//     is reached, extending fails and we send them to the login screen with a clear reason.
import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, refreshSession, sessionState } from "@/api";
import { Modal, PrimaryBtn, GhostBtn } from "./ui";
import { t } from "./i18n";

const POLL_MS = 15_000;          // how often we re-check the clock
const IDLE_MS = 60_000;          // no interaction for this long ⇒ treat the operator as idle
const ACTIVITY = ["mousedown", "keydown", "scroll", "touchstart"] as const;

function mmss(s: number): string {
  const t = Math.max(0, Math.round(s));
  return `${Math.floor(t / 60)}:${String(t % 60).padStart(2, "0")}`;
}

export function useSessionGuard(onExpired: (reason: string) => void) {
  const [warnAt, setWarnAt] = useState<number | null>(null);   // seconds left, when warning
  const [busy, setBusy] = useState(false);
  const lastActive = useRef(Date.now());
  const expiresAt = useRef<number | null>(null);               // epoch ms
  const warnSecs = useRef(120);
  const cap = useRef<{ age: number; max: number }>({ age: 0, max: Infinity });

  useEffect(() => {
    const bump = () => { lastActive.current = Date.now(); };
    ACTIVITY.forEach((e) => window.addEventListener(e, bump, { passive: true }));
    return () => ACTIVITY.forEach((e) => window.removeEventListener(e, bump));
  }, []);

  const extend = useCallback(async (): Promise<boolean> => {
    setBusy(true);
    try {
      const ttl = await refreshSession();
      expiresAt.current = Date.now() + ttl * 1000;
      setWarnAt(null);
      return true;
    } catch (e) {
      // Past the absolute cap (or already dead): the only honest move is to say so.
      onExpired(e instanceof ApiError && e.status === 401
        ? (e.message || t("Your session reached its maximum length. Please sign in again.", "بلغت جلستك الحد الأقصى لمدتها. يرجى تسجيل الدخول مرة أخرى."))
        : t("Your session could not be extended. Please sign in again.", "تعذّر تمديد جلستك. يرجى تسجيل الدخول مرة أخرى."));
      return false;
    } finally { setBusy(false); }
  }, [onExpired]);

  useEffect(() => {
    let stop = false;

    const sync = async () => {
      const s = await sessionState().catch(() => null);
      if (!s || stop) return;
      expiresAt.current = Date.now() + s.expires_in * 1000;
      warnSecs.current = s.warn_seconds;
      cap.current = { age: s.session_age, max: s.absolute_max };
    };

    const tick = async () => {
      if (stop || expiresAt.current == null) return;
      const left = (expiresAt.current - Date.now()) / 1000;
      const idle = Date.now() - lastActive.current > IDLE_MS;
      // Renewing would exceed the absolute cap ⇒ do not pretend we can extend.
      const capReached = cap.current.age + left >= cap.current.max;

      if (left <= 0) {
        onExpired(t("Your session expired. Please sign in again.", "انتهت صلاحية جلستك. يرجى تسجيل الدخول مرة أخرى."));
        return;
      }
      if (!idle && !capReached && left < warnSecs.current * 2) {
        await extend();                      // active operator: renew silently, no interruption
        return;
      }
      if (left <= warnSecs.current) {
        setWarnAt(left);                     // idle (or capped): warn, with a countdown
      }
    };

    sync();
    const poll = setInterval(tick, POLL_MS);
    const resync = setInterval(sync, 5 * 60_000);   // keep the clock honest against the server
    return () => { stop = true; clearInterval(poll); clearInterval(resync); };
  }, [extend, onExpired]);

  // Tighten the countdown once the warning is up.
  useEffect(() => {
    if (warnAt == null) return;
    const timer = setInterval(() => {
      if (expiresAt.current == null) return;
      const left = (expiresAt.current - Date.now()) / 1000;
      if (left <= 0) onExpired(t("Your session expired. Please sign in again.", "انتهت صلاحية جلستك. يرجى تسجيل الدخول مرة أخرى."));
      else setWarnAt(left);
    }, 1000);
    return () => clearInterval(timer);
  }, [warnAt, onExpired]);

  const capReached = warnAt != null &&
    cap.current.age + warnAt >= cap.current.max;

  const modal = warnAt == null ? null : (
    <Modal title={t("Your session is about to expire", "جلستك على وشك الانتهاء")} onClose={() => { /* must decide */ }} width={400}>
      <div className="flex flex-col gap-3">
        <div className="text-3xl font-semibold text-black tabular-nums">{mmss(warnAt)}</div>
        <p className="text-xs text-black/60 leading-5">
          {capReached
            ? t("This session has reached its maximum length, so it cannot be extended. Sign in again to continue — any approval you were reviewing is still in the queue.", "بلغت هذه الجلسة الحد الأقصى لمدتها، ولذلك لا يمكن تمديدها. سجّل الدخول مرة أخرى للمتابعة — أي موافقة كنت تراجعها لا تزال في قائمة الانتظار.")
            : t("You have been idle, so the console is about to sign you out. Anything you were reviewing is safe; extending keeps you where you are.", "كنت خاملاً، ولذلك توشك وحدة التحكم على تسجيل خروجك. أي شيء كنت تراجعه محفوظ؛ التمديد يبقيك في مكانك.")}
        </p>
        <div className="flex gap-2 justify-end">
          <GhostBtn onClick={() => onExpired(t("Signed out.", "تم تسجيل الخروج."))}>{t("Sign out now", "تسجيل الخروج الآن")}</GhostBtn>
          {!capReached && (
            <PrimaryBtn onClick={extend} disabled={busy}>
              {busy ? t("Extending…", "جارٍ التمديد…") : t("Stay signed in", "البقاء مسجّلاً")}
            </PrimaryBtn>
          )}
        </div>
      </div>
    </Modal>
  );

  return { modal };
}

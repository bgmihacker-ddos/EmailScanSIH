import React, { useState } from "react";
import { Play, ShieldAlert, RefreshCw } from "lucide-react";
import { apiFetch } from "../services/api";

export const SimulateAttack: React.FC = () => {
  const [scenario, setScenario] = useState("phishing");
  const [senderName, setSenderName] = useState("Microsoft Security");
  const [senderEmail, setSenderEmail] = useState("security@m1crosoft-alert.com");
  const [subject, setSubject] = useState("Urgent: Verify Your Account");
  const [bodyText, setBodyText] = useState("Please click the link to verify your account credentials immediately.");
  const [spfPass, setSpfPass] = useState(false);
  const [dkimPass, setDkimPass] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);

  const handleSimulate = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setResult(null);
    try {
      const data = await apiFetch("/api/simulate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scenario,
          sender_name: senderName,
          sender_email: senderEmail,
          subject,
          body_text: bodyText,
          spf_pass: spfPass,
          dkim_pass: dkimPass,
        }),
      });
      setResult(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const loadPreset = (key: string) => {
    setScenario(key);
    if (key === "phishing") {
      setSubject("Security Alert: Unusual Sign-in Activity");
      setSenderName("Microsoft Security");
      setSenderEmail("security@m1crosoft-alert.com");
      setBodyText("We detected unusual sign-in activity. Verify here: http://evil.com/login");
    } else if (key === "bec") {
      setSubject("Urgent Wire Transfer Required");
      setSenderName("CEO Office");
      setSenderEmail("ceo@company-internal.com");
      setBodyText("Process wire transfer of $45,000 immediately. Keep confidential.");
    } else if (key === "india_kyc") {
      setSubject("KYC Update Mandatory – Account Will Be Suspended");
      setSenderName("SBI Yono Support");
      setSenderEmail("support@sbi-yono-update.in");
      setBodyText("Dear Customer, Your KYC is pending. Update Aadhaar details within 24 hours.");
    } else if (key === "quishing") {
      setSubject("Scan to Confirm Your Delivery");
      setSenderName("Courier Delivery Desk");
      setSenderEmail("delivery@parcel-confirm.example");
      setBodyText("Your parcel is waiting. Scan the QR code in the attached notice to confirm delivery and avoid a return fee.");
    } else if (key === "benign") {
      setSubject("Your monthly account statement is ready");
      setSenderName("Example Bank Statements");
      setSenderEmail("statements@example-bank.test");
      setBodyText("Your monthly statement is ready in online banking. You can sign in through the usual bookmarked website.");
      setSpfPass(true);
      setDkimPass(true);
    }
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto pb-12">
      <div className="flex justify-between items-center bg-surface border border-hairline p-6 rounded-2xl">
        <div>
          <h1 className="text-2xl font-bold text-accent">Red Team Attack Simulation Engine</h1>
          <p className="text-sm text-ink-mute mt-1">Craft synthetic threat payloads and test the detection pipeline in real-time.</p>
        </div>
        <div className="flex gap-2">
          {["phishing", "bec", "india_kyc", "quishing", "benign"].map((k) => (
            <button
              key={k}
              type="button"
              onClick={() => loadPreset(k)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold capitalize transition ${scenario === k ? 'bg-accent text-[#071018]' : 'bg-raised text-accent hover:bg-surface'}`}
            >
              {k.replace("_", " ")}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <form onSubmit={handleSimulate} className="bg-surface border border-hairline rounded-2xl p-6 space-y-4">
          <h3 className="text-sm font-semibold text-accent uppercase tracking-wider mb-2">Payload Parameters</h3>

          <div>
            <label className="block text-xs font-medium text-ink-dim mb-1">Sender Name</label>
            <input type="text" value={senderName} onChange={(e) => setSenderName(e.target.value)} className="w-full bg-sunken border border-hairline rounded-lg px-3 py-2 text-sm text-ink-dim focus:border-accent outline-none" />
          </div>

          <div>
            <label className="block text-xs font-medium text-ink-dim mb-1">Sender Email</label>
            <input type="text" value={senderEmail} onChange={(e) => setSenderEmail(e.target.value)} className="w-full bg-sunken border border-hairline rounded-lg px-3 py-2 text-sm text-ink-dim focus:border-accent outline-none" />
          </div>

          <div>
            <label className="block text-xs font-medium text-ink-dim mb-1">Subject</label>
            <input type="text" value={subject} onChange={(e) => setSubject(e.target.value)} className="w-full bg-sunken border border-hairline rounded-lg px-3 py-2 text-sm text-ink-dim focus:border-accent outline-none" />
          </div>

          <div>
            <label className="block text-xs font-medium text-ink-dim mb-1">Email Body Text</label>
            <textarea rows={4} value={bodyText} onChange={(e) => setBodyText(e.target.value)} className="w-full bg-sunken border border-hairline rounded-lg p-3 text-sm text-ink-dim focus:border-accent outline-none" />
          </div>

          <div className="flex gap-4 pt-2">
            <label className="flex items-center gap-2 text-xs text-ink-dim cursor-pointer">
              <input type="checkbox" checked={spfPass} onChange={(e) => setSpfPass(e.target.checked)} className="rounded bg-sunken border-hairline text-accent" /> SPF Pass
            </label>
            <label className="flex items-center gap-2 text-xs text-ink-dim cursor-pointer">
              <input type="checkbox" checked={dkimPass} onChange={(e) => setDkimPass(e.target.checked)} className="rounded bg-sunken border-hairline text-accent" /> DKIM Pass
            </label>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full mt-4 py-3 bg-accent hover:brightness-110 text-[#071018] font-semibold rounded-xl text-sm transition flex items-center justify-center gap-2 shadow-lg"
          >
            {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            Run Attack Simulation
          </button>
        </form>

        <div className="bg-surface border border-hairline rounded-2xl p-6 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-semibold text-accent uppercase tracking-wider mb-4">Simulation Results & Verdict</h3>
            {!result ? (
              <div className="h-64 flex flex-col items-center justify-center text-ink-faint border border-dashed border-hairline rounded-xl">
                <ShieldAlert className="w-8 h-8 mb-2 opacity-40 text-accent" />
                <p className="text-sm">Configure parameters and run simulation to view analysis output.</p>
              </div>
            ) : (
              <div className="space-y-4 animate-fade-in">
                <div className="flex justify-between items-center p-3 bg-sunken border border-hairline rounded-xl">
                  <div>
                    <span className="text-xs text-ink-mute">Verdict</span>
                    <h4 className="text-lg font-bold uppercase text-accent">{result.analysis?.verdict || "Unknown"}</h4>
                  </div>
                  <div className="text-right">
                    <span className="text-xs text-ink-mute">Risk Score</span>
                    <h4 className="text-lg font-bold text-medium">{result.analysis?.risk_score || 0}/100</h4>
                  </div>
                </div>

                <div className="bg-sunken border border-hairline rounded-xl p-3 space-y-2">
                  <span className="text-xs font-semibold text-ink-mute">Summary</span>
                  <p className="text-xs text-ink-dim">{result.analysis?.summary || "No summary provided."}</p>
                </div>

                <div className="bg-sunken border border-hairline rounded-xl p-3 space-y-2">
                  <span className="text-xs font-semibold text-ink-mute">Findings Triggered ({result.analysis?.findings?.length || 0})</span>
                  <div className="max-h-40 overflow-y-auto space-y-1 pr-1">
                    {(result.analysis?.findings || []).map((f: any, i: number) => (
                      <div key={i} className="text-xs p-2 bg-raised rounded border border-accent/20 flex justify-between">
                        <span>{f.title}</span>
                        <span className="text-accent uppercase">{f.severity}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
          <div className="text-xs text-ink-faint pt-4 border-t border-hairline text-center">
            Simulated payloads execute in isolation against the real pipeline.
          </div>
        </div>
      </div>
    </div>
  );
};

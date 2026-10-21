import { useEffect } from "react";
import { useStore } from "../state/store";
import { IconStop } from "./icons";

/**
 * The scans and the fuzz jobs that are running, and what they found.
 */
export default function ScanStatusView() {
  const scanJobs = useStore((s) => s.scanJobs);
  const fuzzJobs = useStore((s) => s.fuzzJobs);
  const refreshScanJobs = useStore((s) => s.refreshScanJobs);
  const refreshFuzzJobs = useStore((s) => s.refreshFuzzJobs);
  const stopScanJob = useStore((s) => s.stopScanJob);
  const stopFuzzJob = useStore((s) => s.stopFuzzJob);
  const setView = useStore((s) => s.setView);

  useEffect(() => {
    void refreshScanJobs();
    void refreshFuzzJobs();
  }, [refreshScanJobs, refreshFuzzJobs]);

  const running = scanJobs.filter((job) => job.status === "running" || job.status === "pending");

  return (
    <div className="scan-status">
      <div className="pane-header">
        <span className="muted grow">
          {running.length} running · {scanJobs.length} scans · {fuzzJobs.length} fuzz jobs
        </span>
        <button className="button" onClick={() => void refreshScanJobs()}>
          Refresh
        </button>
        <button className="button" onClick={() => setView("scanner")}>
          Open the scanner
        </button>
      </div>

      <div className="table-wrap">
        <table className="traffic-table">
          <thead>
            <tr>
              <th className="col-time">Started</th>
              <th className="col-method">Kind</th>
              <th className="col-host">Target</th>
              <th className="col-path">Progress</th>
              <th className="col-status">Status</th>
              <th className="col-size">Findings</th>
              <th className="col-time" />
            </tr>
          </thead>
          <tbody>
            {scanJobs.map((job) => (
              <tr key={job.id}>
                <td className="col-time">
                  {new Date(job.created_at * 1000).toLocaleTimeString(undefined, { hour12: false })}
                </td>
                <td className="col-method">scan</td>
                <td className="col-host mono" title={job.targets.join(", ")}>
                  {job.targets[0] ?? "—"}
                  {job.targets.length > 1 ? ` +${job.targets.length - 1}` : ""}
                </td>
                <td className="col-path">
                  {job.completed}/{job.total} checks
                </td>
                <td className="col-status">
                  <span className={`status ${statusTone(job.status)}`}>{job.status}</span>
                </td>
                <td className="col-size">{job.findings.length}</td>
                <td className="col-time">
                  {job.status === "running" && (
                    <button className="button" onClick={() => void stopScanJob(job.id)}>
                      <IconStop size={12} />
                    </button>
                  )}
                </td>
              </tr>
            ))}

            {fuzzJobs.map((job) => (
              <tr key={job.id}>
                <td className="col-time">
                  {new Date(job.created_at * 1000).toLocaleTimeString(undefined, { hour12: false })}
                </td>
                <td className="col-method">fuzz</td>
                <td className="col-host mono" title={job.template.url}>
                  {job.template.url || "—"}
                </td>
                <td className="col-path">
                  {job.completed}/{job.total} payloads
                </td>
                <td className="col-status">
                  <span className={`status ${statusTone(job.status)}`}>{job.status}</span>
                </td>
                <td className="col-size">
                  {job.results.filter((result) => result.interesting).length}
                </td>
                <td className="col-time">
                  {job.status === "running" && (
                    <button className="button" onClick={() => void stopFuzzJob(job.id)}>
                      <IconStop size={12} />
                    </button>
                  )}
                </td>
              </tr>
            ))}

            {scanJobs.length === 0 && fuzzJobs.length === 0 && (
              <tr>
                <td colSpan={7} className="empty">
                  No scan or fuzz job has been run yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function statusTone(status: string): string {
  if (status === "running") return "warn";
  if (status === "finished") return "ok";
  if (status === "failed") return "error";
  return "info";
}

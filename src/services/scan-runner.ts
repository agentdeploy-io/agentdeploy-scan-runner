import { getEnv } from "../env.js";
import { logger } from "../logger.js";

type ScanTask = {
  jobId: string;
  run: () => Promise<void>;
};

let activeWorkers = 0;
const queue: ScanTask[] = [];
const queuedJobIds = new Set<string>();
const runningJobIds = new Set<string>();
const cancelledJobIds = new Set<string>();

function getLimits() {
  const env = getEnv();
  return {
    maxParallel: env.SCAN_MAX_PARALLEL_JOBS_PER_INSTANCE,
    maxQueued: env.SCAN_MAX_QUEUE_JOBS_PER_INSTANCE,
  };
}

function drainQueue(): void {
  const { maxParallel } = getLimits();

  while (activeWorkers < maxParallel && queue.length > 0) {
    const task = queue.shift();
    if (!task) continue;

    queuedJobIds.delete(task.jobId);
    runningJobIds.add(task.jobId);
    activeWorkers += 1;

    void task
      .run()
      .catch((err) => {
        logger.error({ err, jobId: task.jobId }, "Scan worker task failed");
      })
      .finally(() => {
        cancelledJobIds.delete(task.jobId);
        runningJobIds.delete(task.jobId);
        activeWorkers -= 1;
        drainQueue();
      });
  }
}

export function enqueueScanJob(jobId: string, run: () => Promise<void>): boolean {
  const { maxQueued } = getLimits();

  if (cancelledJobIds.has(jobId)) {
    return false;
  }

  if (queuedJobIds.has(jobId) || runningJobIds.has(jobId)) {
    return true;
  }

  if (queue.length >= maxQueued) {
    return false;
  }

  queue.push({ jobId, run });
  queuedJobIds.add(jobId);
  drainQueue();
  return true;
}

export function cancelScanJob(jobId: string): { wasQueued: boolean; wasRunning: boolean } {
  const wasQueued = queuedJobIds.has(jobId);
  const wasRunning = runningJobIds.has(jobId);

  cancelledJobIds.add(jobId);

  if (wasQueued) {
    const index = queue.findIndex((task) => task.jobId === jobId);
    if (index >= 0) {
      queue.splice(index, 1);
    }
    queuedJobIds.delete(jobId);
  }

  return { wasQueued, wasRunning };
}

export function isScanJobCancelled(jobId: string): boolean {
  return cancelledJobIds.has(jobId);
}

export function clearCancelledScanJob(jobId: string): void {
  cancelledJobIds.delete(jobId);
}

export function getScanRunnerStats() {
  const { maxParallel, maxQueued } = getLimits();
  return {
    activeWorkers,
    queuedJobs: queue.length,
    maxParallel,
    maxQueued,
  };
}

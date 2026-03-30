import { Hono } from "hono";
import { z } from "zod";
declare const scanRequestSchema: z.ZodObject<{
    templateId: z.ZodEffects<z.ZodUnion<[z.ZodString, z.ZodNumber]>, string, string | number>;
    sellerId: z.ZodString;
    sourceRepo: z.ZodString;
    purchaseId: z.ZodOptional<z.ZodString>;
    buyerId: z.ZodOptional<z.ZodString>;
    targetRepo: z.ZodOptional<z.ZodString>;
    githubInstallationId: z.ZodOptional<z.ZodNumber>;
}, "strip", z.ZodTypeAny, {
    templateId: string;
    sellerId: string;
    sourceRepo: string;
    purchaseId?: string | undefined;
    buyerId?: string | undefined;
    targetRepo?: string | undefined;
    githubInstallationId?: number | undefined;
}, {
    templateId: string | number;
    sellerId: string;
    sourceRepo: string;
    purchaseId?: string | undefined;
    buyerId?: string | undefined;
    targetRepo?: string | undefined;
    githubInstallationId?: number | undefined;
}>;
export type ScanRequest = z.infer<typeof scanRequestSchema>;
export declare const scanRoute: Hono<import("hono/types").BlankEnv, import("hono/types").BlankSchema, "/">;
export interface ScanMaintenanceSweepResult {
    checked: number;
    staleReset: number;
    githubReconciled: number;
    errors: number;
}
export declare function runScanMaintenanceSweep(maxJobs?: number): Promise<ScanMaintenanceSweepResult>;
export {};

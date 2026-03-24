import { Hono } from "hono";
import { z } from "zod";
declare const scanRequestSchema: z.ZodObject<{
    templateId: z.ZodEffects<z.ZodUnion<[z.ZodString, z.ZodNumber]>, string, string | number>;
    sellerId: z.ZodString;
    sourceRepo: z.ZodString;
    purchaseId: z.ZodEffects<z.ZodOptional<z.ZodString>, string | undefined, string | undefined>;
    buyerId: z.ZodEffects<z.ZodOptional<z.ZodString>, string | undefined, string | undefined>;
    targetRepo: z.ZodEffects<z.ZodOptional<z.ZodString>, string | undefined, string | undefined>;
}, "strip", z.ZodTypeAny, {
    templateId: string;
    sourceRepo: string;
    sellerId: string;
    purchaseId?: string | undefined;
    buyerId?: string | undefined;
    targetRepo?: string | undefined;
}, {
    templateId: string | number;
    sourceRepo: string;
    sellerId: string;
    purchaseId?: string | undefined;
    buyerId?: string | undefined;
    targetRepo?: string | undefined;
}>;
export type ScanRequest = z.infer<typeof scanRequestSchema>;
export declare const scanRoute: Hono<import("hono/types").BlankEnv, import("hono/types").BlankSchema, "/">;
export {};

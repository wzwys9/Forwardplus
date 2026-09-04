import { z } from "zod";
import { FORWARD_TYPES } from "../../shared/forwardTypes";

export const forwardTypeSchema = z.enum(FORWARD_TYPES);

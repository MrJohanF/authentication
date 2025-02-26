import { z } from 'zod';

const registerSchema = z.object({
  email: z.string().email('Please provide a valid email'),
  password: z.string().min(6, 'Password must be at least 6 characters'),
  name: z.string().optional()
});

const loginSchema = z.object({
  email: z.string().email('Please provide a valid email'),
  password: z.string().min(1, 'Password is required')
});

export { registerSchema, loginSchema };

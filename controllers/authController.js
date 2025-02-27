import bcrypt from 'bcryptjs';
import { PrismaClient } from '@prisma/client';
import { SignJWT } from 'jose';
import { registerSchema, loginSchema } from '../validation/authSchema.js';

const prisma = new PrismaClient();

// Helper to create JWT
const createToken = async (userId) => {
  const token = await new SignJWT({ userId })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('1d')
    .sign(new TextEncoder().encode(process.env.JWT_SECRET));
  
  return token;
};

// Register a new user
export const register = async (req, res) => {
  try {
    const validation = registerSchema.safeParse(req.body);
    if (!validation.success) {
      return res.status(400).json({ 
        message: 'Validation error', 
        errors: validation.error.errors 
      });
    }

    const { email, password, name } = validation.data;
    
    const existingUser = await prisma.user.findUnique({
      where: { email }
    });

    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        name
      },
      select: {
        id: true,
        email: true,
        name: true,
        createdAt: true
      }
    });

    const token = await createToken(user.id);

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none',
      domain: '.ucommerce.live',
      maxAge: 24 * 60 * 60 * 1000 
    });

    res.status(201).json({
      message: 'User registered successfully',
      user
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

// Login user
export const login = async (req, res) => {
  try {
    const validation = loginSchema.safeParse(req.body);
    if (!validation.success) {
      return res.status(400).json({ 
        message: 'Validation error', 
        errors: validation.error.errors 
      });
    }

    const { email, password } = validation.data;

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = await createToken(user.id);

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none',
      domain: '.ucommerce.live',
      maxAge: 24 * 60 * 60 * 1000 
    });

    res.json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

// Logout user
export const logout = (req, res) => {
  // Log the incoming cookies for debugging
  console.log('Incoming cookies on logout:', req.cookies);
  
  // Clear the cookie with very explicit options
  res.clearCookie('token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'none',
    domain: '.ucommerce.live',
    path: '/'
  });
  
  // For localhost testing
  if (req.headers.origin && req.headers.origin.includes('localhost')) {
    res.clearCookie('token', {
      httpOnly: true,
      sameSite: 'lax',
      path: '/'
    });
  }
  
  // Set an expired cookie as a backup approach
  res.cookie('token', '', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'none',
    domain: '.ucommerce.live',
    path: '/',
    maxAge: 1 // Set to expire immediately
  });
  
  // Log that we're attempting to clear
  console.log('Attempting to clear token cookie');
  
  res.json({ message: 'Logged out successfully' });
};

// Get current user
export const me = (req, res) => {
  if (!req.user) {
    return res.status(401).json({ message: 'Not authenticated' });
  }
  res.json({ user: req.user });
};
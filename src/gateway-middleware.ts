import JWT from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';
import { IAuthPayload } from './interfaces/auth.interface';
import { IAuthDocument } from './interfaces/auth.interface';
import { IOrderDocument } from './interfaces/order.interface';
import { IReviewDocument } from './interfaces/review.interface';
import { NotAuthorizedError } from './error-handler';

const tokens: string[] = [
  'auth',
  'seller',
  'gig',
  'search',
  'buyer',
  'message',
  'order',
  'review',
];

export function verifyGatewayRequest(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  if (req.headers?.gatewayToken) {
    throw new NotAuthorizedError(
      'gateway token does not exists',
      'gateway middleware'
    );
  }
  const token: string = req.headers?.gatewayToken as string;
  if (!token) {
    throw new NotAuthorizedError('Invalid token', 'gateway middleware');
  }
  try {
    const payload: { id: string; iat: number } = JWT.verify(token, '') as {
      id: string;
      iat: number;
    };
    if (!tokens.includes(payload.id)) {
      throw new NotAuthorizedError('Invalid token', 'gateway middleware');
    }
  } catch (err) {
    throw new NotAuthorizedError('Invalid token', 'gateway middleware');
  }
}

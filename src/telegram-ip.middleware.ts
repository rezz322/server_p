import { Injectable, NestMiddleware, ForbiddenException, Logger } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import * as crypto from 'crypto';

@Injectable()
export class TelegramIpMiddleware implements NestMiddleware {
    private readonly logger = new Logger(TelegramIpMiddleware.name);

    // Official Telegram IP ranges
    private readonly telegramIpRanges = [
        '149.154.160.0/20',
        '91.108.4.0/22',
        '2001:b28:f23d::/48',
        '2001:b28:f23f::/48',
        '2001:67c:4e8::/48',
    ];

    use(req: Request, res: Response, next: NextFunction) {
        const clientIp = this.getClientIp(req);

        // 1. Allow GET requests by key without signature
        const urlSegments = req.originalUrl.split('?')[0].split('/').filter(s => s !== '');
        const isGetByKey = req.method === 'GET' && (
            (urlSegments.length === 2 && urlSegments[0] === 'accounts' && !['get-available-accounts', 'user-keys'].includes(urlSegments[1])) ||
            (urlSegments.length === 3 && urlSegments[0] === 'accounts' && urlSegments[1] === 'key') ||
            (urlSegments.length === 3 && urlSegments[0] === 'accounts' && urlSegments[1] === 'key-check-ban')
        );

        if (isGetByKey) {
            return next();
        }

        // 2. Verify HMAC Signature
        const signature = req.headers['x-signature'] as string;
        const timestamp = req.headers['x-timestamp'] as string;

        if (!signature || !timestamp) {
            this.logger.warn(`Missing security headers from IP: ${clientIp}`);
            throw new ForbiddenException('Missing security headers');
        }

        // Prevent replay attacks (allow 5 minute window)
        const now = Math.floor(Date.now() / 1000);
        const reqTime = parseInt(timestamp, 10);
        if (isNaN(reqTime) || Math.abs(now - reqTime) > 300) {
            this.logger.warn(`Expired or invalid timestamp: ${timestamp} from IP: ${clientIp}`);
            throw new ForbiddenException('Request expired');
        }

        const secret = process.env.SIGNING_SECRET;
        if (!secret) {
            this.logger.error('SIGNING_SECRET is not defined in .env');
            throw new ForbiddenException('Server configuration error');
        }

        // HMAC signature base: timestamp + method + originalUrl
        const base = `${timestamp}${req.method}${req.originalUrl}`;
        const expectedSignature = crypto
            .createHmac('sha256', secret)
            .update(base)
            .digest('hex');

        if (signature !== expectedSignature) {
            this.logger.warn(`Invalid signature: ${signature} from IP: ${clientIp}`);
            throw new ForbiddenException('Invalid signature');
        }

        return next();
    }

    private getClientIp(req: Request): string {
        const forwardedFor = req.headers['x-forwarded-for'];
        if (forwardedFor) {
            return (Array.isArray(forwardedFor) ? forwardedFor[0] : forwardedFor.split(',')[0]).trim();
        }
        return req.ip || req.connection.remoteAddress || '';
    }

    private isTelegramIp(ip: string): boolean {
        return this.telegramIpRanges.some(range => this.ipInCidr(ip, range));
    }

    private ipInCidr(ip: string, cidr: string): boolean {
        try {
            const [range, bitsStr] = cidr.split('/');
            const bits = parseInt(bitsStr, 10);

            if (range.indexOf('.') !== -1 && ip.indexOf('.') !== -1) {
                // IPv4
                const ipUint32 = this.ipToUint32(ip);
                const rangeUint32 = this.ipToUint32(range);
                const mask = bits === 0 ? 0 : ~(Math.pow(2, 32 - bits) - 1);
                return (ipUint32 & mask) === (rangeUint32 & mask);
            } else if (range.indexOf(':') !== -1 && ip.indexOf(':') !== -1) {
                // IPv6
                const ipExpanded = this.expandIpv6(ip);
                const rangeExpanded = this.expandIpv6(range);
                const fullHexBits = bits / 4;
                return ipExpanded.substring(0, fullHexBits) === rangeExpanded.substring(0, fullHexBits);
            }
        } catch (e) {
            return false;
        }
        return false;
    }

    private ipToUint32(ip: string): number {
        const parts = ip.split('.').map(part => parseInt(part, 10));
        return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
    }

    private expandIpv6(ip: string): string {
        let fullIp = ip;
        if (ip.includes('::')) {
            const [before, after] = ip.split('::');
            const beforeParts = before ? before.split(':') : [];
            const afterParts = after ? after.split(':') : [];
            const middle = Array(8 - beforeParts.length - afterParts.length).fill('0000');
            fullIp = [...beforeParts, ...middle, ...afterParts].join(':');
        }
        return fullIp.split(':').map(part => part.padStart(4, '0')).join('');
    }
}

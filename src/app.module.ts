import { Module, NestModule, MiddlewareConsumer } from '@nestjs/common';
import { BotModule } from './bot/bot.module';
import { PrismaModule } from './prisma/prisma.module';
import { AccountsModule } from './accounts/accounts.module';
import { TelegramUsersModule } from './telegram-users/telegram-users.module';
import { TelegramIpMiddleware } from './telegram-ip.middleware';

@Module({
  imports: [PrismaModule, BotModule, AccountsModule, TelegramUsersModule],
  controllers: [],
  providers: [],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(TelegramIpMiddleware)
      .forRoutes('*');
  }
}

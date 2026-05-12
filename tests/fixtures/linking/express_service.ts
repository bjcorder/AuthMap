import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

export async function createSession(userId: string) {
  return prisma.session.create({
    data: { userId },
  });
}


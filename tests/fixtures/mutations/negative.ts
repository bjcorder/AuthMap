const prisma = {
  user: {
    findMany() {
      return [];
    },
  },
};

export async function readUsers() {
  // prisma.user.delete()
  const text = "delete from users";
  return prisma.user.findMany();
}

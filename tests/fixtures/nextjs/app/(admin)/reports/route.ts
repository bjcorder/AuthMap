function handleDelete() {
  return prisma.report.delete({ where: { id: "report_1" } });
}

export { handleDelete as DELETE };

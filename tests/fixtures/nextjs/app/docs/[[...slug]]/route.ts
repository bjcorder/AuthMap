function requireUser() {
  return true;
}

function updateDoc() {
  return prisma.doc.update({ where: { id: "doc_1" }, data: { title: "Updated" } });
}

export const PUT = requireUser(updateDoc);

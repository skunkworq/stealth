export const metadata = {
  title: "brws Agent Server",
  description: "Chatbot-driven nested-agent research",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="h-screen w-screen overflow-hidden bg-[#0f1117] text-[#c9cdd6]">
        {children}
      </body>
    </html>
  );
}

import './globals.css'

export const metadata = {
  title: 'Cloud Security',
  description: 'Compare agent-based and agentless cloud security scanning tools with real-time threat detection',
}

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        {children}
      </body>
    </html>
  )
}
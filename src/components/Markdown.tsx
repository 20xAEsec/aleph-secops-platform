"use client";

import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

// GFM autolinks bare domains and email addresses. In a security report that is actively harmful:
// an indicator the agents just flagged would render as a clickable link to the flagged host, and
// principals would become mailto: links. Autolinks are rendered as plain indicator text instead;
// an explicit [label](url) the agents write on purpose still renders as a link.
const isAutolink = (href: string, children: React.ReactNode) => {
  const text = Array.isArray(children) ? children.join("") : String(children ?? "");
  return href.replace(/^(https?:\/\/|mailto:)/, "").replace(/\/$/, "") === text.replace(/\/$/, "");
};

export default function Markdown({ text, streaming = false }: { text: string; streaming?: boolean }) {
  return (
    <div className={`prose-aleph ${streaming ? "caret" : ""}`}>
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          a({ href, children, ...props }) {
            if (href && isAutolink(href, children)) {
              return <span className="indicator">{children}</span>;
            }
            return <a href={href} rel="noopener noreferrer nofollow" target="_blank" {...props}>{children}</a>;
          },
        }}
      >
        {text}
      </ReactMarkdown>
    </div>
  );
}

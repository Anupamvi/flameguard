"use client";

import { useState, useRef, useEffect, useCallback } from "react";
import Markdown from "react-markdown";
import { useAudits } from "@/hooks/use-audit";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Loader2, Send, Bot, User, MessageSquare, Shield, Lightbulb, HelpCircle } from "lucide-react";

const BASE_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

const STARTER_QUESTIONS = [
  { label: "What is zero-trust architecture?", icon: Shield },
  { label: "Best practices for Azure NSG rules?", icon: Lightbulb },
  { label: "How to segment a 3-tier app network?", icon: MessageSquare },
  { label: "Explain CIS Azure benchmark for NSGs", icon: Shield },
] as const;

export default function ChatPage() {
  const { data: audits, isLoading: auditsLoading } = useAudits();
  const [selectedAuditId, setSelectedAuditId] = useState("");
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [isStreaming, setIsStreaming] = useState(false);
  const [conversationId, setConversationId] = useState<string | undefined>();
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // "general" mode when no audit is selected
  const isGeneralMode = !selectedAuditId;

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const handleSend = useCallback(async (overrideMessage?: string) => {
    const trimmed = (overrideMessage ?? input).trim();
    if (!trimmed || isStreaming) return;

    // In audit mode, require audit selection
    if (!isGeneralMode && !selectedAuditId) return;

    const userMessage: ChatMessage = { role: "user", content: trimmed };
    setMessages((prev) => [...prev, userMessage]);
    if (!overrideMessage) setInput("");
    setIsStreaming(true);

    // Add an empty assistant message that we will stream into
    setMessages((prev) => [...prev, { role: "assistant", content: "" }]);

    // Choose endpoint based on mode
    const endpoint = isGeneralMode
      ? `${BASE_URL}/chat/general`
      : `${BASE_URL}/audit/${selectedAuditId}/chat`;

    try {
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: trimmed,
          conversation_id: conversationId,
        }),
      });

      if (!res.ok) {
        let detail = `API error: ${res.status}`;
        try {
          const body = await res.json() as { detail?: unknown };
          if (typeof body.detail === "string" && body.detail.trim()) {
            detail = body.detail;
          }
        } catch {
          // Ignore non-JSON error payloads.
        }
        throw new Error(detail);
      }

      const reader = res.body?.getReader();
      if (!reader) throw new Error("No readable stream");

      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";

        for (const line of lines) {
          const trimmedLine = line.trim();
          if (!trimmedLine.startsWith("data:")) continue;
          const jsonStr = trimmedLine.slice(5).trim();
          if (!jsonStr) continue;

          try {
            const data = JSON.parse(jsonStr) as Record<string, unknown>;

            if (data.conversation_id) {
              setConversationId(data.conversation_id as string);
            }

            if (data.done) {
              break;
            }

            if (data.error) {
              throw new Error(data.error as string);
            }

            if (data.content) {
              setMessages((prev) => {
                const updated = [...prev];
                const last = updated[updated.length - 1];
                if (last && last.role === "assistant") {
                  updated[updated.length - 1] = {
                    ...last,
                    content: last.content + (data.content as string),
                  };
                }
                return updated;
              });
            }
          } catch {
            // skip unparseable SSE lines
          }
        }
      }
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : "Unknown error";
      setMessages((prev) => {
        const updated = [...prev];
        const last = updated[updated.length - 1];
        if (last && last.role === "assistant" && last.content === "") {
          updated[updated.length - 1] = {
            ...last,
            content: `Error: ${errorMsg}`,
          };
        } else {
          updated.push({ role: "assistant", content: `Error: ${errorMsg}` });
        }
        return updated;
      });
    } finally {
      setIsStreaming(false);
    }
  }, [input, selectedAuditId, isStreaming, conversationId, isGeneralMode]);

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  }

  const chatTitle = isGeneralMode
    ? "General Policy Chat"
    : `Chat about: ${audits?.find((a) => a.id === selectedAuditId)?.filename}`;

  return (
    <div className="flex h-[calc(100vh-theme(spacing.12))] flex-col">
      <div className="mb-4">
        <h2 className="fg-page-title">
          Policy Chat
        </h2>
        <p className="fg-page-subtitle max-w-none">
          Ask questions about security policies, audit findings, or general network security
        </p>
      </div>

      {/* What this tool does */}
      <div className="mb-4 rounded-xl border border-white/[0.06] bg-gradient-to-br from-surface-700 to-surface-800 px-5 py-4">
        <div className="flex items-start gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-flame-500/10">
            <HelpCircle className="h-5 w-5 text-flame-400" />
          </div>
          <div>
            <p className="fg-panel-title">How Policy Chat helps you</p>
            <p className="fg-panel-body">
              <strong className="text-gray-300">General mode:</strong> Ask about Azure networking best practices, CIS benchmarks, zero-trust architecture, or segmentation strategies without uploading anything.{" "}
              <strong className="text-gray-300">Audit mode:</strong> Select an audit below to ask targeted questions about specific findings &mdash; get remediation guidance, understand severity ratings, or generate fix commands for your exact configuration.
            </p>
          </div>
        </div>
      </div>

      <div className="mb-4">
        <label className="mb-1 block text-sm font-medium text-gray-300">
          Context
        </label>
        <select
          value={selectedAuditId}
          onChange={(e) => {
            setSelectedAuditId(e.target.value);
            setMessages([]);
            setConversationId(undefined);
          }}
          disabled={auditsLoading}
          className="h-10 w-full max-w-md rounded-lg border border-white/[0.1] bg-surface-700 px-3 text-base text-gray-200 outline-none focus:border-flame-500/50 focus:ring-2 focus:ring-flame-500/20"
        >
          <option value="">General — no audit context</option>
          {audits?.map((audit) => (
            <option key={audit.id} value={audit.id}>
              {audit.filename} ({audit.vendor}) - {audit.status}
            </option>
          ))}
        </select>
      </div>

      <Card className="flex flex-1 flex-col overflow-hidden">
        <CardHeader className="border-b pb-3">
          <CardTitle className="text-base">{chatTitle}</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-1 flex-col overflow-hidden p-0">
          {/* Messages area */}
          <div className="flex-1 overflow-y-auto p-4">
            {messages.length === 0 && (
              <div className="flex h-full flex-col items-center justify-center gap-4">
                <Bot className="h-10 w-10 text-gray-600" />
                <p className="text-base text-gray-500">
                  {isGeneralMode
                    ? "Ask anything about security policies, compliance, and network security."
                    : "Ask a question about this audit to get started."}
                </p>
                {isGeneralMode && (
                  <div className="mt-2 flex flex-wrap justify-center gap-2">
                    {STARTER_QUESTIONS.map(({ label, icon: Icon }) => (
                      <button
                        key={label}
                        type="button"
                        onClick={() => handleSend(label)}
                        className="flex items-center gap-1.5 rounded-full border border-white/[0.06] bg-surface-700 px-3 py-2 text-sm font-medium text-gray-300 transition-colors hover:border-white/[0.15] hover:bg-surface-600"
                      >
                        <Icon className="h-3 w-3" />
                        {label}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            )}
            <div className="space-y-4">
              {messages.map((msg, i) => (
                <div
                  key={i}
                  className={`flex gap-3 ${
                    msg.role === "user" ? "justify-end" : "justify-start"
                  }`}
                >
                  {msg.role === "assistant" && (
                    <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-flame-500/10">
                      <span className="text-sm">🔥</span>
                    </div>
                  )}
                  <div
                    className={`max-w-[80%] rounded-2xl px-4 py-3 text-base leading-relaxed ${
                      msg.role === "user"
                        ? "rounded-br-md bg-flame-600 text-white"
                        : "rounded-bl-md border border-white/[0.06] bg-surface-700 text-gray-300"
                    }`}
                  >
                    {msg.role === "assistant" ? (
                      <div className="prose prose-invert max-w-none prose-headings:mb-2 prose-headings:mt-3 prose-headings:text-gray-100 prose-p:my-1.5 prose-ul:my-1.5 prose-ol:my-1.5 prose-li:my-0.5 prose-code:rounded prose-code:bg-white/[0.06] prose-code:px-1 prose-code:py-0.5 prose-code:text-sm prose-code:text-flame-300 prose-pre:rounded-md prose-pre:bg-surface-900 prose-pre:text-gray-300">
                        <Markdown>{msg.content}</Markdown>
                      </div>
                    ) : (
                      <p className="whitespace-pre-wrap">{msg.content}</p>
                    )}
                    {msg.role === "assistant" && msg.content === "" && isStreaming && (
                      <Loader2 className="h-4 w-4 animate-spin text-gray-500" />
                    )}
                  </div>
                  {msg.role === "user" && (
                    <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-flame-600">
                      <User className="h-4 w-4 text-white" />
                    </div>
                  )}
                </div>
              ))}
              <div ref={messagesEndRef} />
            </div>
          </div>

          {/* Input area */}
          <div className="border-t p-4">
            <div className="flex gap-2">
              <Textarea
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder={
                  isGeneralMode
                    ? "Ask about policy best practices, compliance, segmentation..."
                    : "Ask about this audit..."
                }
                disabled={isStreaming}
                className="min-h-[40px] flex-1 resize-none"
                rows={1}
              />
              <Button
                onClick={() => handleSend()}
                disabled={isStreaming || !input.trim()}
                size="icon"
              >
                {isStreaming ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Send className="h-4 w-4" />
                )}
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

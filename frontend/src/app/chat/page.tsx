"use client";

import { useState, useRef, useEffect, useCallback } from "react";
import { useAudits } from "@/hooks/use-audit";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Loader2, Send, Bot, User } from "lucide-react";

const BASE_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

export default function ChatPage() {
  const { data: audits, isLoading: auditsLoading } = useAudits();
  const [selectedAuditId, setSelectedAuditId] = useState("");
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [isStreaming, setIsStreaming] = useState(false);
  const [conversationId, setConversationId] = useState<string | undefined>();
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const handleSend = useCallback(async () => {
    const trimmed = input.trim();
    if (!trimmed || !selectedAuditId || isStreaming) return;

    const userMessage: ChatMessage = { role: "user", content: trimmed };
    setMessages((prev) => [...prev, userMessage]);
    setInput("");
    setIsStreaming(true);

    // Add an empty assistant message that we will stream into
    setMessages((prev) => [...prev, { role: "assistant", content: "" }]);

    try {
      const res = await fetch(`${BASE_URL}/audits/${selectedAuditId}/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: trimmed,
          conversation_id: conversationId,
        }),
      });

      if (!res.ok) {
        throw new Error(`API error: ${res.status}`);
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
            const data = JSON.parse(jsonStr);

            if (data.conversation_id) {
              setConversationId(data.conversation_id);
            }

            if (data.done) {
              break;
            }

            if (data.content) {
              setMessages((prev) => {
                const updated = [...prev];
                const last = updated[updated.length - 1];
                if (last && last.role === "assistant") {
                  updated[updated.length - 1] = {
                    ...last,
                    content: last.content + data.content,
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
  }, [input, selectedAuditId, isStreaming, conversationId]);

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  }

  return (
    <div className="flex h-[calc(100vh-theme(spacing.14)-theme(spacing.12))] flex-col">
      <div className="mb-4">
        <h2 className="text-2xl font-bold tracking-tight text-slate-900">
          Policy Chat
        </h2>
        <p className="mt-1 text-sm text-slate-500">
          Ask questions about your firewall policies and audit findings
        </p>
      </div>

      <div className="mb-4">
        <label className="mb-1 block text-sm font-medium text-slate-700">
          Select Audit
        </label>
        <select
          value={selectedAuditId}
          onChange={(e) => {
            setSelectedAuditId(e.target.value);
            setMessages([]);
            setConversationId(undefined);
          }}
          disabled={auditsLoading}
          className="h-8 w-full max-w-sm rounded-lg border border-slate-200 bg-white px-2.5 text-sm text-slate-700 outline-none focus:border-slate-400 focus:ring-2 focus:ring-slate-200"
        >
          <option value="">
            {auditsLoading ? "Loading audits..." : "Select an audit..."}
          </option>
          {audits?.map((audit) => (
            <option key={audit.id} value={audit.id}>
              {audit.filename} ({audit.vendor}) - {audit.status}
            </option>
          ))}
        </select>
      </div>

      {!selectedAuditId ? (
        <Card className="flex flex-1 items-center justify-center">
          <CardContent>
            <p className="text-sm text-slate-500">
              Select an audit above to start chatting.
            </p>
          </CardContent>
        </Card>
      ) : (
        <Card className="flex flex-1 flex-col overflow-hidden">
          <CardHeader className="border-b pb-3">
            <CardTitle className="text-sm">
              Chat about: {audits?.find((a) => a.id === selectedAuditId)?.filename}
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-1 flex-col overflow-hidden p-0">
            {/* Messages area */}
            <div className="flex-1 overflow-y-auto p-4">
              {messages.length === 0 && (
                <div className="flex h-full items-center justify-center text-sm text-slate-400">
                  Ask a question about this audit to get started.
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
                      <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-slate-200">
                        <Bot className="h-4 w-4 text-slate-600" />
                      </div>
                    )}
                    <div
                      className={`max-w-[80%] rounded-lg px-3 py-2 text-sm ${
                        msg.role === "user"
                          ? "bg-slate-900 text-white"
                          : "bg-slate-100 text-slate-700"
                      }`}
                    >
                      <p className="whitespace-pre-wrap">{msg.content}</p>
                      {msg.role === "assistant" && msg.content === "" && isStreaming && (
                        <Loader2 className="h-4 w-4 animate-spin text-slate-400" />
                      )}
                    </div>
                    {msg.role === "user" && (
                      <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-slate-900">
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
                  placeholder="Ask about this audit..."
                  disabled={isStreaming}
                  className="min-h-[40px] flex-1 resize-none"
                  rows={1}
                />
                <Button
                  onClick={handleSend}
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
      )}
    </div>
  );
}

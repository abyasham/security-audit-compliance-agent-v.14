import { useState, useRef, useEffect } from 'react';
import { useStore } from '../../store';

interface Props {
  disabled?: boolean;
}

export function ChatInput({ disabled }: Props) {
  const [input, setInput] = useState('');
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const { sendMessage, isStreaming } = useStore();

  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
      textareaRef.current.style.height = Math.min(textareaRef.current.scrollHeight, 120) + 'px';
    }
  }, [input]);

  const handleSubmit = async () => {
    const trimmed = input.trim();
    if (!trimmed || disabled || isStreaming) return;

    setInput('');
    await sendMessage(trimmed);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSubmit();
    }
  };

  return (
    <div className="flex gap-2 items-end">
      <textarea
        ref={textareaRef}
        value={input}
        onChange={(e) => setInput(e.target.value)}
        onKeyDown={handleKeyDown}
        placeholder="Ask SACA about compliance violations..."
        rows={1}
        disabled={disabled || isStreaming}
        className="input-field resize-none flex-1 min-h-[44px] max-h-[120px] py-3"
      />
      <button
        onClick={handleSubmit}
        disabled={!input.trim() || disabled || isStreaming}
        className="btn-primary h-[44px] px-6 flex items-center gap-2"
      >
        {isStreaming ? (
          <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
        ) : (
          'Send'
        )}
      </button>
    </div>
  );
}

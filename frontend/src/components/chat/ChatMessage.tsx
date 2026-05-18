import ReactMarkdown from 'react-markdown';
import { ChatMessage as ChatMessageType } from '../../types';

interface Props {
  message: ChatMessageType;
}

export function ChatMessage({ message }: Props) {
  const isUser = message.role === 'user';

  return (
    <div className={`flex ${isUser ? 'justify-end' : 'justify-start'}`}>
      <div
        className={`max-w-[85%] rounded-xl px-4 py-3 ${
          isUser
            ? 'bg-saca-700 text-white rounded-br-sm'
            : 'bg-gray-800 text-gray-200 rounded-bl-sm'
        }`}
      >
        {!isUser && (
          <div className="flex items-center gap-2 mb-2 text-xs text-gray-500">
            <img src="/saca.jpg" className="h-5 w-auto object-contain rounded" alt="SACA" />
            <span className="font-medium text-saca-300">SACA</span>
          </div>
        )}
        <div className="prose prose-invert prose-sm max-w-none">
          <ReactMarkdown>{message.content}</ReactMarkdown>
        </div>
      </div>
    </div>
  );
}

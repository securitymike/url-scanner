'use strict';

// Detection signatures for file-sharing and AI capability. Domains match the host itself and any subdomain.
// Extend these lists as your organisation's policy requires.

const FILE_SHARING_DOMAINS = {
  // Cloud storage / sync
  'dropbox.com': 'cloud storage', 'dropboxusercontent.com': 'cloud storage', 'db.tt': 'cloud storage',
  'box.com': 'cloud storage', 'boxcdn.net': 'cloud storage',
  'drive.google.com': 'cloud storage', 'docs.google.com': 'document sharing', 'drive.usercontent.google.com': 'cloud storage',
  'onedrive.live.com': 'cloud storage', '1drv.ms': 'cloud storage', 'onedrive.com': 'cloud storage', 'sharepoint.com': 'document sharing',
  'icloud.com': 'cloud storage', 'pcloud.com': 'cloud storage', 'sync.com': 'cloud storage', 'tresorit.com': 'cloud storage',
  'idrive.com': 'cloud storage', 'mega.nz': 'cloud storage', 'mega.io': 'cloud storage', 'mega.co.nz': 'cloud storage',
  'koofr.eu': 'cloud storage', 'drive.proton.me': 'cloud storage', 'terabox.com': 'cloud storage',
  'disk.yandex.com': 'cloud storage', 'disk.yandex.ru': 'cloud storage', 'nextcloud.com': 'cloud storage', 'egnyte.com': 'cloud storage',
  // File transfer
  'wetransfer.com': 'file transfer', 'we.tl': 'file transfer', 'fromsmash.com': 'file transfer', 'filemail.com': 'file transfer',
  'sendgb.com': 'file transfer', 'swisstransfer.com': 'file transfer', 'transfernow.net': 'file transfer', 'hightail.com': 'file transfer',
  'send-anywhere.com': 'file transfer', 'sendanywhere.com': 'file transfer', 'transfer.sh': 'file transfer', 'file.io': 'file transfer',
  'wormhole.app': 'file transfer', 'jumpshare.com': 'file transfer', 'masv.io': 'file transfer', 'filetransfer.io': 'file transfer',
  'sendspace.com': 'file transfer', 'dropsend.com': 'file transfer', 'tinyupload.com': 'file transfer',
  // File hosting / lockers
  'mediafire.com': 'file hosting', '4shared.com': 'file hosting', 'zippyshare.com': 'file hosting', 'rapidgator.net': 'file hosting',
  'uploaded.net': 'file hosting', 'nitroflare.com': 'file hosting', 'turbobit.net': 'file hosting', 'gofile.io': 'file hosting',
  'anonfiles.com': 'file hosting', 'bayfiles.com': 'file hosting', 'pixeldrain.com': 'file hosting', 'catbox.moe': 'file hosting',
  'filebin.net': 'file hosting', 'ufile.io': 'file hosting', 'uploadfiles.io': 'file hosting', 'krakenfiles.com': 'file hosting',
  '1fichier.com': 'file hosting', 'workupload.com': 'file hosting', 'filedropper.com': 'file hosting', 'files.fm': 'file hosting',
  'uploadhaven.com': 'file hosting', 'dosya.co': 'file hosting', 'userscloud.com': 'file hosting',
  'imgur.com': 'image hosting', 'imgbb.com': 'image hosting', 'postimages.org': 'image hosting', 'flickr.com': 'image hosting',
  'scribd.com': 'document sharing', 'slideshare.net': 'document sharing', 'issuu.com': 'document sharing', 'docsend.com': 'document sharing',
  // Paste sites
  'pastebin.com': 'paste site', 'paste.ee': 'paste site', 'hastebin.com': 'paste site', 'ghostbin.co': 'paste site',
  'rentry.co': 'paste site', 'controlc.com': 'paste site', 'justpaste.it': 'paste site', 'privatebin.net': 'paste site',
  // Code / artifact hosting
  'github.com': 'code & file hosting', 'raw.githubusercontent.com': 'code & file hosting', 'gist.github.com': 'code & file hosting',
  'githubusercontent.com': 'code & file hosting', 'gitlab.com': 'code & file hosting', 'bitbucket.org': 'code & file hosting',
  'sourceforge.net': 'file hosting',
  // Messaging / collaboration with file transfer
  'discord.com': 'messaging with file sharing', 'cdn.discordapp.com': 'file hosting', 'discordapp.com': 'messaging with file sharing',
  't.me': 'messaging with file sharing', 'telegram.org': 'messaging with file sharing', 'web.telegram.org': 'messaging with file sharing',
  'web.whatsapp.com': 'messaging with file sharing', 'slack.com': 'messaging with file sharing', 'teams.microsoft.com': 'messaging with file sharing',
  'teams.live.com': 'messaging with file sharing',
};

// Third-party upload widgets / libraries. Matched against script URLs, request domains and inline script content.
const UPLOAD_LIBRARY_PATTERNS = [
  { label: 'Dropzone.js', re: /dropzone(\.min)?\.js|\bnew Dropzone\(|Dropzone\.options/i },
  { label: 'FilePond', re: /filepond/i },
  { label: 'Uppy', re: /\buppy\b|releases\.transloadit\.com\/uppy/i },
  { label: 'Fine Uploader', re: /fine-?uploader/i },
  { label: 'Plupload', re: /plupload/i },
  { label: 'Resumable.js', re: /resumable(\.min)?\.js|\bnew Resumable\(/i },
  { label: 'tus resumable upload', re: /tus-js-client|\bnew tus\.Upload\(/i },
  { label: 'jQuery File Upload', re: /jquery\.fileupload/i },
  { label: 'Uploadcare', re: /uploadcare/i },
  { label: 'Filestack', re: /filestack/i },
  { label: 'Transloadit', re: /transloadit/i },
  { label: 'Cloudinary Upload Widget', re: /upload-widget\.cloudinary\.com/i },
];

// Object-storage hosts. A page talking to these may be storing or serving user files.
const STORAGE_HOST_PATTERNS = [
  { label: 'Amazon S3', re: /(^|\.)s3([.-][a-z0-9-]+)*\.amazonaws\.com$/i },
  { label: 'Azure Blob Storage', re: /\.blob\.core\.windows\.net$/i },
  { label: 'Google Cloud Storage', re: /^storage\.googleapis\.com$/i },
  { label: 'Firebase Storage', re: /^firebasestorage\.googleapis\.com$/i },
  { label: 'Cloudflare R2', re: /\.r2\.(cloudflarestorage\.com|dev)$/i },
  { label: 'DigitalOcean Spaces', re: /\.digitaloceanspaces\.com$/i },
  { label: 'Backblaze B2', re: /\.backblazeb2\.com$/i },
];

const DOWNLOAD_EXTENSION_RE = /\.(zip|rar|7z|tar|gz|tgz|bz2|xz|exe|msi|dmg|pkg|apk|ipa|iso|img|jar|bat|cmd|ps1|scr|vbs)$/i;

const FILE_SHARING_KEYWORDS = [
  { label: '"upload files"', re: /\bupload (your |a |the )?(files?|documents?|photos?|videos?)\b/i },
  { label: '"file sharing" / "share files"', re: /\bfile[- ]sharing\b|\bshare (your )?(files?|documents?|folders?)\b/i },
  { label: '"file transfer" / "send files"', re: /\bfile transfer\b|\bsend (large |big )?files\b/i },
  { label: '"drag and drop files"', re: /\bdrag (and|&|n) drop (your )?files?\b|\bdrop (your )?files? here\b/i },
  { label: '"shareable/download link"', re: /\b(shareable|sharing|download) link\b/i },
  { label: '"cloud storage"', re: /\bcloud storage\b|\bstore (your )?files\b/i },
];

const FILE_SHARING_CATEGORY_RE = /file.?shar|file.?host|file.?transfer|file.?download|online.?storage|cloud.?storage|personal.?storage|storage.?service|peer.?to.?peer|\bp2p\b|web.?storage/i;

const AI_SERVICE_DOMAINS = {
  'openai.com': 'OpenAI', 'chatgpt.com': 'ChatGPT', 'sora.com': 'OpenAI Sora', 'oaiusercontent.com': 'OpenAI',
  'anthropic.com': 'Anthropic', 'claude.ai': 'Claude', 'claude.com': 'Claude',
  'gemini.google.com': 'Google Gemini', 'bard.google.com': 'Google Gemini', 'aistudio.google.com': 'Google AI Studio',
  'notebooklm.google.com': 'Google NotebookLM', 'labs.google': 'Google Labs', 'deepmind.google': 'Google DeepMind',
  'copilot.microsoft.com': 'Microsoft Copilot', 'copilot.cloud.microsoft': 'Microsoft 365 Copilot', 'm365copilot.com': 'Microsoft 365 Copilot',
  'perplexity.ai': 'Perplexity', 'poe.com': 'Poe', 'character.ai': 'Character.AI', 'huggingface.co': 'Hugging Face', 'hf.space': 'Hugging Face Spaces',
  'replicate.com': 'Replicate', 'midjourney.com': 'Midjourney', 'stability.ai': 'Stability AI', 'dreamstudio.ai': 'Stability AI',
  'runwayml.com': 'Runway', 'pika.art': 'Pika', 'leonardo.ai': 'Leonardo.Ai', 'ideogram.ai': 'Ideogram', 'krea.ai': 'Krea', 'civitai.com': 'Civitai',
  'jasper.ai': 'Jasper', 'copy.ai': 'Copy.ai', 'writesonic.com': 'Writesonic', 'grammarly.com': 'Grammarly', 'quillbot.com': 'QuillBot',
  'deepl.com': 'DeepL', 'deepseek.com': 'DeepSeek', 'mistral.ai': 'Mistral AI', 'cohere.com': 'Cohere', 'cohere.ai': 'Cohere',
  'x.ai': 'xAI', 'grok.com': 'Grok', 'meta.ai': 'Meta AI', 'you.com': 'You.com', 'phind.com': 'Phind', 'pi.ai': 'Pi',
  'together.ai': 'Together AI', 'groq.com': 'Groq', 'fireworks.ai': 'Fireworks AI', 'openrouter.ai': 'OpenRouter',
  'elevenlabs.io': 'ElevenLabs', 'synthesia.io': 'Synthesia', 'heygen.com': 'HeyGen', 'descript.com': 'Descript',
  'otter.ai': 'Otter.ai', 'fireflies.ai': 'Fireflies.ai', 'gamma.app': 'Gamma', 'tome.app': 'Tome', 'beautiful.ai': 'Beautiful.ai',
  'cursor.com': 'Cursor', 'codeium.com': 'Codeium', 'windsurf.com': 'Windsurf', 'tabnine.com': 'Tabnine', 'v0.dev': 'v0', 'v0.app': 'v0',
  'lovable.dev': 'Lovable', 'bolt.new': 'Bolt', 'replit.com': 'Replit', 'suno.com': 'Suno', 'udio.com': 'Udio',
  'chatbase.co': 'Chatbase', 'typingmind.com': 'TypingMind', 'janitorai.com': 'JanitorAI', 'manus.im': 'Manus',
  'kimi.com': 'Kimi', 'moonshot.cn': 'Moonshot AI', 'qwen.ai': 'Qwen', 'tongyi.aliyun.com': 'Tongyi Qianwen', 'doubao.com': 'Doubao',
};

// Hosts of AI inference APIs. A page (or its scripts) calling these is integrating an AI model.
const AI_API_HOST_PATTERNS = [
  { label: 'OpenAI API', re: /^api\.openai\.com$/i },
  { label: 'Azure OpenAI', re: /\.openai\.azure\.com$/i },
  { label: 'Azure AI Services', re: /\.(cognitiveservices\.azure\.com|services\.ai\.azure\.com|inference\.ai\.azure\.com)$/i },
  { label: 'Anthropic API', re: /^api\.anthropic\.com$/i },
  { label: 'Google Gemini API', re: /^generativelanguage\.googleapis\.com$/i },
  { label: 'Google Vertex AI', re: /(^|\.)aiplatform\.googleapis\.com$/i },
  { label: 'AWS Bedrock', re: /^bedrock-runtime(-fips)?\.[a-z0-9-]+\.amazonaws\.com$/i },
  { label: 'Cohere API', re: /^api\.cohere\.(ai|com)$/i },
  { label: 'Mistral API', re: /^api\.mistral\.ai$/i },
  { label: 'Hugging Face Inference', re: /^(api-inference|router)\.huggingface\.co$/i },
  { label: 'Replicate API', re: /^api\.replicate\.com$/i },
  { label: 'Together API', re: /^api\.together\.(xyz|ai)$/i },
  { label: 'Groq API', re: /^api\.groq\.com$/i },
  { label: 'Perplexity API', re: /^api\.perplexity\.ai$/i },
  { label: 'DeepSeek API', re: /^api\.deepseek\.com$/i },
  { label: 'xAI API', re: /^api\.x\.ai$/i },
  { label: 'OpenRouter API', re: /^openrouter\.ai$/i },
  { label: 'ElevenLabs API', re: /^api\.elevenlabs\.io$/i },
];

// AI chatbot / assistant widget vendors embedded in third-party sites.
const AI_WIDGET_PATTERNS = [
  { label: 'Chatbase chatbot', re: /(^|\.)chatbase\.co$/i },
  { label: 'Botsonic (Writesonic) chatbot', re: /(^|\.)writesonic\.com$/i },
  { label: 'Voiceflow assistant', re: /(^|\.)voiceflow\.com$/i },
  { label: 'Botpress chatbot', re: /(^|\.)botpress\.(cloud|com)$/i },
  { label: 'Ada AI agent', re: /(^|\.)ada\.support$/i },
  { label: 'Drift conversational AI', re: /(^|\.)driftt?\.com$/i },
  { label: 'Tidio (Lyro AI)', re: /(^|\.)tidio\.co$/i },
  { label: 'Intercom (Fin AI agent)', re: /(^|\.)(intercom\.io|intercomcdn\.com)$/i },
  { label: 'Kore.ai', re: /(^|\.)kore\.ai$/i },
  { label: 'Yellow.ai', re: /(^|\.)yellow\.ai$/i },
  { label: 'Forethought', re: /(^|\.)forethought\.ai$/i },
  { label: 'Kapa.ai', re: /(^|\.)kapa\.ai$/i },
  { label: 'Inkeep AI search', re: /(^|\.)inkeep\.com$/i },
  { label: 'Mendable', re: /(^|\.)mendable\.ai$/i },
  { label: 'DocsBot', re: /(^|\.)docsbot\.ai$/i },
  { label: 'CustomGPT', re: /(^|\.)customgpt\.ai$/i },
  { label: 'SiteGPT', re: /(^|\.)sitegpt\.ai$/i },
  { label: 'Chatling', re: /(^|\.)chatling\.ai$/i },
  { label: 'Landbot', re: /(^|\.)landbot\.io$/i },
];

const AI_KEYWORDS = [
  { label: '"artificial intelligence"', re: /\bartificial intelligence\b/i },
  { label: '"generative AI"', re: /\bgenerative ai\b|\bgen ?ai\b/i },
  { label: '"AI-powered/AI assistant"', re: /\bai[- ](powered|driven|assistant|agent|agents|chatbot|generated|generator|copilot|writer|model|models|features?)\b/i },
  { label: '"LLM / large language model"', re: /\blarge language models?\b|\bLLMs?\b/ },
  { label: '"machine learning"', re: /\bmachine learning\b/i },
  { label: '"ChatGPT/GPT"', re: /\bchat ?gpt\b|\bgpt-?(3\.5|4o?|4\.1|5)\b/i },
  { label: '"chatbot"', re: /\bchat ?bots?\b/i },
];

const AI_STRONG_TEXT_RE = /\b(powered by|built (with|on)|using) (openai|chat ?gpt|gpt-?\d|claude|anthropic|gemini|llama|mistral|azure openai|copilot)\b/i;

// Patterns searched in inline <script> content (ids are recorded by the extractor).
const INLINE_SCRIPT_PATTERNS = [
  ...UPLOAD_LIBRARY_PATTERNS.map((p) => ({ id: `upload:${p.label}`, re: p.re })),
  { id: 'ai:openai-sdk', re: /\bapi\.openai\.com\b|\bopenai\.azure\.com\b|\bdangerouslyAllowBrowser\b/i },
  { id: 'ai:anthropic-sdk', re: /\bapi\.anthropic\.com\b/i },
  { id: 'ai:gemini-sdk', re: /\bgenerativelanguage\.googleapis\.com\b|@google\/generative-ai|@google\/genai/i },
  { id: 'ai:model-names', re: /["'](gpt-4o?(-mini)?|gpt-4\.1|gpt-5|claude-[a-z0-9.-]+|gemini-[0-9.]+-[a-z]+)["']/i },
];

const AI_CATEGORY_RE = /artificial.?intelligence|generative.?ai|\bai\b|chat.?bot|machine.?learning|\bllm\b/i;

module.exports = {
  FILE_SHARING_DOMAINS,
  UPLOAD_LIBRARY_PATTERNS,
  STORAGE_HOST_PATTERNS,
  DOWNLOAD_EXTENSION_RE,
  FILE_SHARING_KEYWORDS,
  FILE_SHARING_CATEGORY_RE,
  AI_SERVICE_DOMAINS,
  AI_API_HOST_PATTERNS,
  AI_WIDGET_PATTERNS,
  AI_KEYWORDS,
  AI_STRONG_TEXT_RE,
  AI_CATEGORY_RE,
  INLINE_SCRIPT_PATTERNS,
};

import Image from "next/image";

export default function PictionaryTip() {
  return (
    <div className="mt-6 rounded-2xl border border-teal/10 bg-white/70 p-5 sm:p-6">
      <h3 className="font-display text-lg font-bold text-teal">
        Pro tip: draw compound words visually
      </h3>
      <p className="mt-2 text-sm text-teal/80">
        For tricky compound or hidden words, use position instead of extra
        letters. Here, the word &quot;stand&quot; drawn under a line reads as
        &quot;under&quot; + &quot;stand&quot; — understand. Try the same
        trick with size, direction, and repetition to hint at word
        combinations without writing anything extra.
      </p>
      <div className="mt-4 overflow-hidden rounded-xl border border-teal/10 bg-white">
        <Image
          src="/pictionary-tip.png"
          alt='The word "stand" drawn with a line above it — a Pictionary trick for illustrating "understand"'
          width={1448}
          height={1086}
          className="w-full h-auto"
        />
      </div>
    </div>
  );
}

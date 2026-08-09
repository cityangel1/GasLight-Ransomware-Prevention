import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft, Users, Clock, Package } from "lucide-react";
import Header from "@/components/Header";
import Footer from "@/components/Footer";
import ChessBasics from "@/components/ChessBasics";
import PictionaryTip from "@/components/PictionaryTip";
import GameDetailActions from "@/components/GameDetailActions";
import { getAllGames, getGameBySlug } from "@/lib/games";
import {
  AGE_LABELS,
  DURATION_LABELS,
  MATERIALS_LABELS,
  TYPE_LABELS,
} from "@/lib/types";

export async function generateStaticParams() {
  const games = await getAllGames();
  return games.map((g) => ({ slug: g.slug }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  const game = await getGameBySlug(slug);
  if (!game) return {};
  return {
    title: `${game.title} — Awesome Games`,
    description: game.tagline,
  };
}

function playerRangeLabel(min: number, max: number | null) {
  if (max === null) return `${min}+ players`;
  if (min === max) return `${min} players`;
  return `${min}-${max} players`;
}

export default async function GamePage({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  const game = await getGameBySlug(slug);
  if (!game) notFound();

  return (
    <>
      <Header />
      <main className="flex-1">
        <div className="mx-auto max-w-3xl px-5 sm:px-8 py-10">
          <Link
            href="/"
            className="inline-flex items-center gap-1.5 text-sm font-semibold text-brown hover:text-orange transition-colors"
          >
            <ArrowLeft size={16} strokeWidth={2.5} />
            Back to all games
          </Link>

          <div className="mt-6 flex items-start justify-between gap-4 flex-wrap">
            <div>
              <h1 className="font-display text-3xl sm:text-4xl font-extrabold text-teal">
                {game.title}
              </h1>
              <p className="mt-2 text-teal/70 text-lg">{game.tagline}</p>
            </div>
            <GameDetailActions slug={game.slug} title={game.title} />
          </div>

          <div className="mt-6 flex flex-wrap gap-2">
            {game.types.map((t) => (
              <span
                key={t}
                className="rounded-full bg-teal-tint text-teal px-3 py-1 text-xs font-semibold"
              >
                {TYPE_LABELS[t]}
              </span>
            ))}
          </div>

          <div className="mt-6 grid grid-cols-2 sm:grid-cols-4 gap-3">
            <InfoStat
              icon={<Users size={18} strokeWidth={2.5} />}
              label="Players"
              value={playerRangeLabel(game.minPlayers, game.maxPlayers)}
            />
            <InfoStat
              icon={<Clock size={18} strokeWidth={2.5} />}
              label="Duration"
              value={DURATION_LABELS[game.duration]}
            />
            <InfoStat
              icon={<Package size={18} strokeWidth={2.5} />}
              label="Materials"
              value={game.materials.map((m) => MATERIALS_LABELS[m]).join(", ")}
            />
            <InfoStat
              icon={<Users size={18} strokeWidth={2.5} />}
              label="Best for"
              value={game.ageGroups.map((a) => AGE_LABELS[a]).join(", ")}
            />
          </div>

          <div className="mt-10 rounded-2xl bg-white/70 border border-teal/10 p-6 sm:p-8">
            <h2 className="font-display text-xl font-bold text-teal">
              How to play
            </h2>
            <ol className="mt-4 space-y-4">
              {game.instructions.map((step, i) => (
                <li key={i} className="flex gap-3">
                  <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-orange text-cream font-display font-bold text-sm">
                    {i + 1}
                  </span>
                  <p className="text-teal/85 pt-0.5">{step}</p>
                </li>
              ))}
            </ol>

            {game.tips && game.tips.trim() && (
              <div className="mt-6 rounded-xl bg-teal-tint p-4">
                <p className="text-sm text-teal">
                  <span className="font-bold">Tip: </span>
                  {game.tips.trim()}
                </p>
              </div>
            )}
            {game.slug === "chess" && (
  <ChessBasics />
)}
            {game.slug === "pictionary" && <PictionaryTip />}
          </div>
        </div>
      </main>
      <Footer />
    </>
  );
}

function InfoStat({
  icon,
  label,
  value,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
}) {
  return (
    <div className="rounded-xl bg-white/60 border border-teal/10 p-3">
      <div className="flex items-center gap-1.5 text-brown">
        {icon}
        <span className="text-[11px] font-bold uppercase tracking-wide">
          {label}
        </span>
      </div>
      <p className="mt-1 text-sm font-semibold text-teal">{value}</p>
    </div>
  );
}

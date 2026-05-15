import { motion } from 'framer-motion';

const MEMBERS = [
  {
    id: 'M1',
    name: 'Mohammad Hudib',
    initials: 'MH',
    color: '#ff1744',
    role: 'Endpoint Agent',
    ownership: ['watchdog', 'inotify events', 'SIGSTOP pipeline', 'containment engine'],
    techStack: ['Python', 'inotify-simple', 'psutil', 'ctypes', 'signal', 'subprocess'],
  },
  {
    id: 'M2',
    name: 'Mahmoud Hussein',
    initials: 'MH',
    color: '#ffd700',
    role: 'Graph & EVP Engine',
    ownership: ['networkx graph', 'scipy entropy', 'canary placement', 'EVP algorithm'],
    techStack: ['NetworkX', 'SciPy', 'NumPy', 'Markov chains', 'Shannon entropy'],
  },
  {
    id: 'M3',
    name: 'Ahmad Jehad',
    initials: 'AJ',
    color: '#00f5ff',
    role: 'Backend & Dashboard',
    ownership: ['FastAPI server', 'PostgreSQL schema', 'Redis pub/sub', 'React dashboard'],
    techStack: ['FastAPI', 'PostgreSQL', 'Redis', 'Celery', 'React', 'WebSocket'],
  },
  {
    id: 'M4',
    name: 'Adnan Alshrouqi',
    initials: 'AA',
    color: '#b537f2',
    role: 'Detection & Testing',
    ownership: ['lineage scoring', 'adaptive repositioning', 'simulation scripts', 'pytest suite'],
    techStack: ['pytest', 'Python', 'bash', 'simulation', 'ML analysis', 'AI integration'],
  },
];

function TeamCard({ member, index }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 60 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, amount: 0.2 }}
      transition={{ duration: 0.6, delay: index * 0.12 }}
      className="flip-card h-72"
      data-hover
    >
      <div className="flip-card-inner">
        {/* Front */}
        <div
          className="flip-card-front glass rounded-2xl p-6 flex flex-col"
          style={{
            border: `1px solid ${member.color}40`,
            boxShadow: `0 0 30px ${member.color}15`,
          }}
        >
          {/* Top strip */}
          <div
            className="absolute top-0 left-0 right-0 h-px rounded-t-2xl"
            style={{ background: `linear-gradient(90deg, transparent, ${member.color}, transparent)` }}
          />

          {/* Avatar + badge */}
          <div className="flex items-center gap-3 mb-4">
            <div
              className="w-12 h-12 rounded-full flex items-center justify-center font-heading font-bold text-base shrink-0"
              style={{
                background: `${member.color}20`,
                border: `2px solid ${member.color}`,
                color: member.color,
                boxShadow: `0 0 20px ${member.color}40`,
              }}
            >
              {member.initials}
            </div>
            <div>
              <div className="font-heading font-bold text-sm text-white">{member.name}</div>
              <div
                className="font-mono text-[10px] tracking-widest"
                style={{ color: member.color }}
              >
                {member.id}
              </div>
            </div>
          </div>

          {/* Role */}
          <h3
            className="font-heading font-bold text-base mb-3"
            style={{ color: member.color, textShadow: `0 0 10px ${member.color}60` }}
          >
            {member.role}
          </h3>

          {/* Ownership list */}
          <ul className="space-y-1.5 flex-1">
            {member.ownership.map((item) => (
              <li key={item} className="flex items-center gap-2">
                <span
                  className="w-1.5 h-1.5 rounded-full shrink-0"
                  style={{ background: member.color, boxShadow: `0 0 6px ${member.color}` }}
                />
                <span className="font-mono text-[11px] text-gray-400">{item}</span>
              </li>
            ))}
          </ul>

          <p className="font-mono text-[9px] text-gray-600 mt-3 text-right">hover to flip →</p>
        </div>

        {/* Back */}
        <div
          className="flip-card-back glass rounded-2xl p-6 flex flex-col justify-center"
          style={{
            border: `1px solid ${member.color}60`,
            boxShadow: `0 0 40px ${member.color}20`,
          }}
        >
          <div className="absolute top-0 left-0 right-0 h-px rounded-t-2xl"
            style={{ background: `linear-gradient(90deg, transparent, ${member.color}, transparent)` }}
          />

          <div
            className="text-4xl font-heading font-bold mb-2 text-center"
            style={{ color: member.color, textShadow: `0 0 30px ${member.color}` }}
          >
            {member.id}
          </div>

          <p className="font-mono text-xs text-gray-400 text-center mb-5">Tech Stack</p>

          <div className="flex flex-wrap gap-2 justify-center">
            {member.techStack.map((tech) => (
              <span
                key={tech}
                className="font-mono text-[10px] px-3 py-1 rounded-full"
                style={{
                  background: `${member.color}18`,
                  border: `1px solid ${member.color}60`,
                  color: member.color,
                }}
              >
                {tech}
              </span>
            ))}
          </div>
        </div>
      </div>
    </motion.div>
  );
}

export default function Team() {
  return (
    <section id="team" className="section py-28 px-6">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="text-center mb-16">
          <motion.p
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true }}
            className="font-mono text-xs tracking-widest text-[#00ff88] mb-3 uppercase"
          >
            The Team
          </motion.p>
          <motion.h2
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0.1 }}
            className="font-heading font-bold"
            style={{ fontSize: 'clamp(1.8rem, 4vw, 3rem)', color: '#fff' }}
          >
            The Team Behind the{' '}
            <span style={{ color: '#00ff88' }}>Shield</span>
          </motion.h2>
        </div>

        {/* Cards grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
          {MEMBERS.map((m, i) => (
            <TeamCard key={m.id} member={m} index={i} />
          ))}
        </div>
      </div>
    </section>
  );
}

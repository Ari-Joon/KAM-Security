type Props = {
  title: string;
  lede: string;
  points: string[];
  phase: string;
};

/**
 * A page for a module that has not been built.
 *
 * It says what it will do and which phase it belongs to, rather than showing an
 * empty dashboard or a fake number. A security tool that displays a reassuring
 * "Protected" when nothing is implemented is exactly the genre this project is
 * meant to be an alternative to.
 */
export default function Planned({ title, lede, points, phase }: Props) {
  return (
    <>
      <div className="view-head">
        <div>
          <h1>{title}</h1>
          <p className="lede">{lede}</p>
        </div>
        <span className="pill pill-idle">{phase}</span>
      </div>

      <section className="panel">
        <div className="panel-head">
          <h2>Not built yet</h2>
        </div>
        <p className="muted">
          Nothing here is running, and nothing on this screen is measuring your
          machine. When it is built, it will do this:
        </p>
        <ul className="planned">
          {points.map((point) => (
            <li key={point}>{point}</li>
          ))}
        </ul>
      </section>
    </>
  );
}

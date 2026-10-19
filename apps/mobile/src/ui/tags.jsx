// The tag picker: the five optional tags an item can carry (core/categories.js). Shared by
// the Add flow's review and the item screen's rename, so it lives in the kit, not the
// add chunk: the vault's first paint must not carry the camera.
import { Icon } from "../brand/icons.jsx";
import { TAGS } from "../core/categories.js";

export function TagPicker({ tags, onChange, label = "Tags (optional)" }) {
  const toggle = (id) => onChange(tags.includes(id) ? tags.filter((t) => t !== id) : [...tags, id]);
  return (
    <div class="field">
      <label>{label}</label>
      <div class="chips" role="group" aria-label="Tags">
        {TAGS.map((t) => <button class="chip" type="button" aria-pressed={tags.includes(t.id)} onClick={() => toggle(t.id)}><Icon name={t.icon} />{t.label}</button>)}
      </div>
    </div>
  );
}

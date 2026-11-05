// What kinds of hidden data a file can carry. Shared by the scrubber and the admin dashboard.
// weight feeds the privacy risk score: how much a category can reveal about the person behind a photo.
export const CATEGORIES = {
  location:    { label: 'Location',            icon: '📍', weight: 40, desc: 'GPS coordinates, altitude, heading, place names' },
  people:      { label: 'People & faces',      icon: '👤', weight: 20, desc: 'Tagged faces and named people' },
  identity:    { label: 'Author & contact',    icon: '🪪', weight: 15, desc: 'Names, copyright, email, phone, address' },
  device:      { label: 'Camera & device',     icon: '📷', weight: 10, desc: 'Make, model, lens and serial numbers' },
  tracking:    { label: 'Unique IDs',          icon: '🔗', weight: 10, desc: 'Document and image IDs that link copies together' },
  ai:          { label: 'AI generation',       icon: '✨', weight: 10, desc: 'Prompts, seeds, models and AI flags' },
  provenance:  { label: 'Content Credentials', icon: '🛡️', weight: 10, desc: 'C2PA manifests, signers and edit actions' },
  hidden:      { label: 'Hidden images',       icon: '🖼️', weight: 10, desc: 'Thumbnails, depth maps, gain maps, motion clips' },
  datetime:    { label: 'Dates & times',       icon: '🕒', weight: 5,  desc: 'When it was taken, edited and saved' },
  description: { label: 'Captions & keywords', icon: '📝', weight: 5,  desc: 'Titles, captions, comments, ratings' },
  software:    { label: 'Software & edits',    icon: '🛠️', weight: 3,  desc: 'Apps used and edit history' },
  capture:     { label: 'Camera settings',     icon: '⚙️', weight: 2,  desc: 'Exposure, aperture, ISO, focal length, flash' },
  color:       { label: 'Colour profile',      icon: '🎨', weight: 1,  desc: 'Embedded ICC profile' },
  other:       { label: 'Other',               icon: '•',  weight: 1,  desc: 'Anything else the file carried' },
};

export const CATEGORY_ORDER = Object.keys(CATEGORIES);

export function riskOf(categories) {
  const score = Math.min(100, categories.reduce((n, c) => n + (CATEGORIES[c]?.weight || 0), 0));
  const level = score >= 40 ? 'high' : score >= 15 ? 'medium' : score > 0 ? 'low' : 'none';
  return { score, level };
}

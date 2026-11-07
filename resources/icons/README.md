# Astroute icons

Compact Voyager-inspired artwork with a teal dish, blue-gray body and gold record.
SVG sources use transparent backgrounds and contain no embedded images or fonts.

- `hicolor/scalable/apps/io.github.astroute.Astroute.svg`: color app icon, 256-unit canvas.
- `hicolor/scalable/apps/io.github.astroute.Astroute-symbolic.svg`: monochrome symbol, 24-unit canvas.
- `hicolor/16x16/apps/io.github.astroute.Astroute-symbolic.svg`: simplified symbol for 16 px.

The installer includes all three assets. Symbolic icons use the foreground color
provided by the desktop theme; the smaller source has wider openings and fewer details.

Export a transparent PNG with librsvg:

```sh
rsvg-convert -w 256 -h 256 hicolor/scalable/apps/io.github.astroute.Astroute.svg -o astroute.png
```

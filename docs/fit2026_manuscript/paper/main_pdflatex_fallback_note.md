# pdfLaTeX fallback note

`main.tex` is the intended manuscript source and uses LuaLaTeX + `ltjsarticle`.

The old pdfLaTeX + `CJKutf8` workaround was removed from `main.tex` because its Japanese font quality is poor. It was only an emergency compatibility workaround for environments that could not be switched to LuaLaTeX.

For Overleaf:

1. Put the contents of this `paper/` folder at the Overleaf project root.
2. Set `Menu -> Compiler -> LuaLaTeX`.
3. Compile `main.tex`.

If Overleaf still reports `luatexja-core requires Lua(HB)(La)TeX`, it is still running pdfLaTeX or LaTeX, not LuaLaTeX.

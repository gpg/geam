
EXTRA_DIST = geamd.sgml geamd-options.sgml manual.de.sgml gloss.de.sgml \
	     version.sgml.in  \
	     geamd.8 manual.de.ps manual.de.html

man_MANS = geamd.8
pkgdata_DATA = manual.de.html manual.de.ps

BUILT_SOURCES = manual.de.html manual.de.ps

CLEANFILES = manual.de.aux manual.de.log manual.de.tex manual.de.dvi

manual.de.sgml : version.sgml gloss.de.sgml geamd-options.sgml


if HAVE_DB2MAN
%.8 : %.sgml
	$(DB2MAN) $<  >$@
endif

if HAVE_DB2TEX
%.ps : %.dvi
	dvips -o $@ $<

%.tex : %.sgml
	$(DB2TEX) -d localstyle.dsl $< > $@

%.dvi : %.tex
	$(JADETEX) $<
endif

if HAVE_DB2HTML
%.html : %.sgml
	$(DB2HTML) --nosplit $<
endif


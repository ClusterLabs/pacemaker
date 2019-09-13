DOCS =
DOCS += data-access-control

DOCS_HTML = $(DOCS:%=%.html)
DOCS_PDF = $(DOCS:%=%.pdf)

all: html

clean:
	-rm -f $(DOCS_HTML) $(DOCS_PDF)

html: $(DOCS_HTML)
pdf: $(DOCS_PDF)

.PHONY: all clean html pdf

PANDOCVARS =
PANDOCVARS += -V colorlinks
PANDOCVARS += -V links-as-notes
PANDOCVARS += -V geometry:margin=2.5cm
PANDOCVARS += -V papersize:a4

# avoid recipe redundancy, since pandoc adapts respectively
# (at the cost of staying compatible with GNU make only)
.SECONDEXPANSION:

$(DOCS_HTML) $(DOCS_PDF): %: $$(basename %).md
	pandoc $< --pdf-engine=xelatex $(PANDOCVARS) -o $@

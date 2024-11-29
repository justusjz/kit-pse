specification: prepare
	pdflatex -output-directory=tmp reports/specification.tex
	mv tmp/specification.pdf out/
clean:
	rm -rf out tmp
prepare:
	mkdir -p out tmp
format:
	latexindent -m -l reports/latexindent.yaml -w reports/specification.tex

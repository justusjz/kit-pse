specification: prepare
	pdflatex -output-directory=tmp reports/specification.tex
	mv tmp/specification.pdf out/
clean:
	rm -rf out tmp
prepare:
	mkdir -p out tmp

template: prepare
	pdflatex -output-directory=tmp reports/techreport.tex
	mv tmp/techreport.pdf out/
clean:
	rm -rf out tmp
prepare:
	mkdir -p out tmp

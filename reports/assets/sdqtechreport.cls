%% LaTeX2e class for technical reports
%% sdqtechreport.cls
%%
%% Karlsruhe Institute of Technology
%% Institute for Program Structures and Data Organization
%% Chair for Software Design and Quality (SDQ)
%%
%% Dr.-Ing. Erik Burger
%% burger@kit.edu
%%
%% See https://sdq.kastel.kit.edu/wiki/Dokumentvorlagen
%%
%% Version 1.0, 2023-11-20

\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{reports/assets/sdqtechreport}[2023-11-20]
\DeclareOption{ngerman}{\PassOptionsToPackage{\CurrentOption}{babel}}
\DeclareOption{english}{\PassOptionsToPackage{main=\CurrentOption,ngerman}{babel}}
\DeclareOption*{\PassOptionsToClass{\CurrentOption}{scrreprt}}
\ProcessOptions\relax

%% ---------------------------------------------------------------
%% | Based on KOMAscript by Markus Kohm http://www.komascript.de |
%% ---------------------------------------------------------------
\LoadClass{scrreprt}

%% --------------
%% | Typography |
%% --------------

% T1 font encoding
\RequirePackage[T1]{fontenc}
\RequirePackage[utf8]{inputenc}

% serif type: Linux Libertine
\RequirePackage{libertine}
% Linux Libertine in math mode
\RequirePackage[libertine]{newtxmath}

% grotesque type: Adobe Source Sans Pro
\RequirePackage[scaled=.92]{sourcesanspro}

% monospace type: Bera Mono
\RequirePackage[scaled=.78]{beramono}

% semi-bold type (for subsections and paragraphs)
\newcommand*{\sbdefault}{sb}
\DeclareRobustCommand{\sbseries}{%
  \not@math@alphabet\sbseries\relax
  \fontseries\sbdefault\selectfont}

\DeclareTextFontCommand{\textsb}{\sbseries}

\addtokomafont{subsection}{\sbseries}
\addtokomafont{subsubsection}{\sbseries}
\addtokomafont{paragraph}{\sbseries}

% microtype for nicer typography
\RequirePackage[protrusion=true,expansion=true]{microtype}

% commands for code and model keywords in text
\newcommand{\code}[1]{\texttt{\hyphenchar\font45\relax #1}}
\newcommand{\model}[1]{\textsf{#1}}

% nicer spacing for enumerations
\RequirePackage{enumitem}

%% -----------
%% | Spacing |
%% -----------

% more flexible spacing for paragraphs
\RedeclareSectionCommands[
    beforeskip= .7em plus .6em minus .3em
]{paragraph}

%% ---------------
%% | Page Layout |
%% ---------------
\KOMAoptions{
   fontsize=12pt,
   paper=a4,
   parskip=half,
   headlines=1.1,
   titlepage=true,
   headinclude=true,
   footinclude=false,
}

\usepackage[automark, headsepline]{scrlayer-scrpage}

%% Größe der Titelzeile
\setkomafont{pageheadfoot}{\footnotesize\usekomafont{pagenumber}}

% Margins
\if@twoside%
  \typearea[20mm]{16} % twoside
\else% 
  \typearea[10mm]{15} % oneside
\fi%

\raggedbottom

\recalctypearea

\clubpenalty=10000 %prevent orphans
\widowpenalty=10000 %prevent widows


%% --------------
%% | Title page |
%% --------------

% Logos
\newcommand{\thegrouplogo}{sdqlogo}
\newcommand{\grouplogo}[1]{\renewcommand{\thegrouplogo}{#1}}
\newcommand{\printgrouplogo}{\includegraphics[height=1.8cm]{reports/assets/logos/\thegrouplogo}}
\newcommand{\nogrouplogo}{\renewcommand{\printgrouplogo}{}}

\titlehead{%
% KIT logo german/english
\ifcurrentbaselanguage{English}
{\includegraphics[height=1.8cm]{reports/assets/logos/kitlogo_en_cmyk}}
{\includegraphics[height=1.8cm]{reports/assets/logos/kitlogo_de_cmyk}}
\hfill
% SDQ logo
\printgrouplogo
\ThisCenterWallPaper{1}{reports/assets/title-background.pdf}
}

%
\setkomafont{title}{\huge\sffamily\bfseries}
\setkomafont{subtitle}{\normalfont\large}

\uppertitleback{Karlsruher Institut für Technologie\\ Fakultät für Informatik\\ Postfach 6980\\ 76128 Karlsruhe}

%% variables for title page
\newcommand{\theinstitute}{\ifcurrentbaselanguage{English}
    {KASTEL -- Institute of Information Security and Dependability}
    {KASTEL -- Institut für Informationssicherheit und Verlässlichkeit}}

%% formatting commands for titlepage
\newcommand{\myinstitute}[1]{\renewcommand{\theinstitute}{#1}}

%% -----------------------------
%% | Abstract/Acknowledgements |
%% -----------------------------

\def\abstractname{Abstract}
\def\switcht@deutsch{\svlanginfo
	\def\abstractname{Kurzfassung}
}
\def\switcht@english{\svlanginfo
	\def\abstractname{Abstract}
}


%% ------------
%% | Packages |
%% ------------

% draft mode
\RequirePackage{ifdraft}
\RequirePackage{ifthen}

% enumerate subsubsections
\setcounter{secnumdepth}{3}

% wallpaper for title page (KIT-Frame)
\RequirePackage{wallpaper}

% subimport of files
\RequirePackage{import}

% languages
\RequirePackage{babel}
\RequirePackage{csquotes}
\RequirePackage{translations}

% hyphenation for compound words
\RequirePackage[shortcuts]{extdash}

% nice tables
\RequirePackage{booktabs}
\RequirePackage{longtable}
\RequirePackage{array}

% show graphics in draft mode
\RequirePackage{graphicx}
\setkeys{Gin}{draft=false}

% appendix
\RequirePackage[toc,title,header]{appendix}
\noappendicestocpagenum

% PDF specific packages
\RequirePackage[hyphens]{url}
\RequirePackage[breaklinks,colorlinks=false]{hyperref}
\newcommand\setpdf{
    \hypersetup{%
    pdftitle={Technical Report},%
    pdfsubject={\@title},%
    pdfauthor={\@author},%
    pdfborder={0 0 0},%
    }%
    \let\theauthor\@author
}


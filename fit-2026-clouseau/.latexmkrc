#!/usr/bin/bash

$out_dir = "out";

$latex = "platex %O %S";
$bibtex = "pbibtex %O %S";
$dvipdf = "dvipdfmx %O -o %D %S";
$makeindex = "mendex %O -o %D %S";

$pdf_mode = 3;

$ENV{"TEXINPUTS"} = "./styles//:" . ($ENV{"TEXINPUTS"} || "");
$ENV{"BIBINPUTS"} = "./contents//:" . ($ENV{"BIBINPUTS"} || "");
$ENV{"BSTINPUTS"} = "./styles//:" . ($ENV{"BSTINPUTS"} || "");

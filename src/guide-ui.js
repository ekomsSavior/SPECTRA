// The guide is editorial content built into the app; no sample text enters its HTML.
let guideChapter=SPECTRA_GUIDE.chapters.find(c=>c.id===new URLSearchParams(location.search).get('guide'))?.id||'start';
const guideSearchText=new Map(SPECTRA_GUIDE.chapters.map(c=>{const fragment=document.createElement('div');fragment.innerHTML=c.body;return [c.id,(c.title+' '+c.summary+' '+fragment.textContent).toLowerCase()];}));
function renderGuideContents(){
 const query=$('guide-search').value.trim().toLowerCase(),terms=query.split(/\s+/).filter(Boolean),matches=SPECTRA_GUIDE.chapters.filter(c=>terms.every(t=>guideSearchText.get(c.id).includes(t)));
 $('guide-match-count').textContent=terms.length?matches.length+' matching chapters':'All '+matches.length+' chapters';
 $('guide-contents').innerHTML=matches.map(c=>'<button type="button" class="guide-chapter-link" data-guide-chapter="'+c.id+'" '+(c.id===guideChapter?'aria-current="page"':'')+'><strong>'+esc(c.title)+'</strong><span>'+esc(c.summary)+'</span></button>').join('')||'<p class="muted">No chapters match. Try a shorter word, or clear the search.</p>';
 $('guide-contents').querySelectorAll('[data-guide-chapter]').forEach(b=>b.onclick=()=>showGuideChapter(b.dataset.guideChapter,true));
}
function showGuideChapter(id,focus=false){
 const index=SPECTRA_GUIDE.chapters.findIndex(c=>c.id===id);if(index<0)return;const c=SPECTRA_GUIDE.chapters[index];guideChapter=id;
 $('guide-article').innerHTML='<header><p class="guide-kicker">CHAPTER '+String(index+1).padStart(2,'0')+' / '+SPECTRA_GUIDE.chapters.length+'</p><h2 id="guide-chapter-title">'+esc(c.title)+'</h2><p class="guide-deck">'+esc(c.summary)+'</p>'+(c.view?'<button type="button" class="button" id="guide-open-section">Open this section →</button>':'')+'</header>'+c.body;
 if(c.view)$('guide-open-section').onclick=()=>{changeView(c.view);$('page-title').scrollIntoView({block:'start'});};
 $('guide-previous').disabled=index===0;$('guide-next').disabled=index===SPECTRA_GUIDE.chapters.length-1;
 $('guide-position').textContent=(index+1)+' / '+SPECTRA_GUIDE.chapters.length;
 renderGuideContents();
 if(focus){const url=new URL(location.href);url.searchParams.set('guide',id);url.hash='lessons';history.replaceState(null,'',url);$('guide-article').focus({preventScroll:true});$('guide-article').scrollIntoView({block:'start'});}
}
$('guide-search').oninput=renderGuideContents;
$('guide-clear').onclick=()=>{$('guide-search').value='';renderGuideContents();$('guide-search').focus();};
for(const [id,delta]of [['guide-previous',-1],['guide-next',1]])$(id).onclick=()=>showGuideChapter(SPECTRA_GUIDE.chapters[SPECTRA_GUIDE.chapters.findIndex(c=>c.id===guideChapter)+delta]?.id,true);
$('guide-edition').textContent=SPECTRA_GUIDE.edition;
if(new URLSearchParams(location.search).has('guide'))$('guide-reader').open=true;
showGuideChapter(guideChapter);

$('guide-exercise-jump').onclick=e=>{e.preventDefault();$('training-exercises').focus({preventScroll:true});$('training-exercises').scrollIntoView({block:'start'});};

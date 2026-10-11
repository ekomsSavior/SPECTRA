const toolMenu=$('touch-tool-menu');
for(const button of document.querySelectorAll('nav[aria-label="Workbench"] [data-view]')){const name=button.dataset.view,option=document.createElement('option');option.value=name;option.textContent=titles[name][2];toolMenu.append(option);}
toolMenu.onchange=()=>{changeView(toolMenu.value);$('page-title').scrollIntoView({block:'start'});};
document.addEventListener('spectra-view',()=>toolMenu.value=state.view);

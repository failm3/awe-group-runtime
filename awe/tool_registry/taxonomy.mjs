// Claims inferred from text; these rules never establish safety, compatibility or permission.
export const RULES=[
 ['browser.screenshot',/(?:playwright|puppeteer|selenium|скриншот|screenshot)/i],
 ['browser.automation',/(?:playwright|puppeteer|selenium|browser.?automat|автоматизац.{0,25}браузер)/i],
 ['document.generate',/(?:pandoc|docx|python-docx|reportlab|pdfkit|генерац.{0,30}документ|создан.{0,30}документ)/i],
 ['document.convert',/(?:pandoc|конверт.{0,30}(?:pdf|документ)|document.?conver)/i],
 ['code.test',/(?:pytest|vitest|jest\b|unittest|test.?runner|тестировани.{0,30}код|тест.{0,20}фреймворк)/i],
 ['code.develop',/(?:\bIDE\b|code.?editor|код.{0,20}редактор|coding|разработк)/i],
 ['mcp.server',/(?:\bmcp\b|model context protocol)/i],
 ['agent.orchestrate',/(?:orchestrat|оркестр|multi.agent|мультиагент)/i],
 ['search.web',/(?:web.?search|поиск.{0,20}интернет|search.?engine|поисковая система)/i],
 ['memory.retrieve',/(?:\bRAG\b|vector.?database|векторн.{0,20}баз|retrieval)/i],
 ['data.store',/(?:postgres|sqlite|database|база данных|базами данных)/i],
 ['security.scan',/(?:vulnerability|уязвимост|security.?scan|антивирус)/i],
 ['media.image',/(?:image|изображен|картинк)/i],
 ['media.audio',/(?:audio|аудио|speech|речи)/i],
 ['media.video',/(?:video|видео)/i],
 ['model.inference',/(?:inference|инференс|llm|языков.{0,10}модел)/i],
 ['infra.observe',/(?:observability|observ|мониторинг|tracing)/i],
 ['backup.restore',/(?:backup|бэкап|резервн.{0,15}коп|restore)/i]
];
export const CAPABILITIES=RULES.map(([name])=>name);
export function classify(row){
 const text=[row.url,row.title,row.description].join(' ');
 const matched=RULES.filter(([,rule])=>rule.test(text)).map(([capability,rule])=>({capability,rule:rule.source,certainty:'INFERRED_FROM_DESCRIPTION'}));
 const hazards=[];
 if(/(?:malware|ransomware|вредонос|jailbreak|обход.{0,20}защит|stealth|ignore.{0,30}(?:instructions|previous)|system prompt|exfiltrat|credential.?steal)/i.test(text))hazards.push('REQUIRES_SECURITY_REVIEW');
 if(/^http:/i.test(row.url??''))hazards.push('CLEARTEXT_SOURCE');
 if(/(?:sudo|curl.{0,80}\|.{0,10}(?:sh|bash)|powershell.{0,30}-enc)/i.test(text))hazards.push('EXECUTION_IN_DESCRIPTION');
 return {capabilities:matched.map(x=>x.capability),rules:matched,hazards,classification:matched.length?'INFERRED':'UNRESOLVED'};
}
export function parseCapabilityRequest(text){
 if(/(?:скриншот|screenshot)/i.test(text))return ['browser.screenshot'];
 if(/(?:документ|document|docx|pdf)/i.test(text))return ['document.generate'];
 if(/(?:тест.{0,15}код|code.{0,15}test|pytest|запуст.{0,15}тест)/i.test(text))return ['code.test'];
 return RULES.filter(([,r])=>r.test(text)).map(([c])=>c);
}

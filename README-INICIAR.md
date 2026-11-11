# Como iniciar o OVBECK no Windows

Este guia explica como abrir a versão local do OVBECK.

## 1. Instale o Node.js

Instale Node.js **22.16.0 ou mais recente** pelo site oficial: https://nodejs.org/. Durante a instalação, deixe habilitada a opção para adicionar Node ao `PATH`. Feche e abra de novo janelas antigas do terminal.

## 2. Extraia o ZIP

1. Baixe `ZIP atualizado da OVBECK`.
2. No Explorador de Arquivos (`Windows + E`), abra Downloads.
3. Clique com o botão direito no ZIP e selecione **Extrair tudo...**.
4. Escolha uma pasta nova chamada `OVBECK`. Não misture os arquivos com a versão antiga.
5. Entre na pasta que acabou de ser extraída.

## 3. Primeira inicialização e administrador

1. Localize `INICIAR_OVBECK.bat` e dê dois cliques.
2. Na primeira abertura, será exibido um assistente para informar o e-mail, o nome de exibição e a senha inicial do administrador. Informe o endereço administrativo que será utilizado na sua instalação local. A senha `A1` pode ser usada somente nesta instalação local; ela será digitada sem aparecer na tela e a troca será obrigatória no primeiro login.
3. O assistente grava as credenciais apenas no arquivo `.env`, que é ignorado pelo Git e não acompanha o ZIP. Nas próximas inicializações, não será necessário informar novamente: o backend verifica a conta e a mantém de forma idempotente.
4. Aguarde a mensagem de que o OVBECK está respondendo e o navegador abrir. Normalmente o endereço é `http://127.0.0.1:4173`.
5. Crie sua conta. **O cadastro não inicia uma sessão**: depois da confirmação local da contratação, entre manualmente com e-mail e senha.

Mantenha a janela do servidor aberta enquanto usa o site. Para encerrar, clique nela e pressione `Ctrl+C`.

## 4. Se ocorrer um erro

- Confira se o Node está instalado: abra PowerShell e execute `node --version`.
- Execute `npm.cmd run verify` dentro da pasta do projeto para rodar as verificações no Windows PowerShell.
- O inicializador verifica se a versão do servidor é a correta e tenta as portas 4173 a 4180.
- Se falhar, envie a mensagem completa da janela e o arquivo `logs\server-startup.log`.
- Não apague a pasta `data` nem o banco para tentar resolver uma falha sem antes fazer uma cópia.

## 5. Iniciar pelo PowerShell

Dentro da pasta do projeto, clique na barra de endereço do Explorador, digite `powershell` e pressione Enter. Depois execute:

```powershell
npm.cmd run verify
npm.cmd start
```

Abra `http://127.0.0.1:4173` (ou a porta mostrada). `Ctrl+C` encerra o servidor.

## 6. Seus dados e migração

Por padrão, usuários, despesas, configurações e simulações ficam em `data\finance.sqlite`. A base é criada automaticamente. O arquivo de banco não está incluído no ZIP.

Se quiser migrar despesas manuais da versão anterior, preserve a pasta antiga e copie `data\store.json` para `data\store.json` nesta versão **antes do primeiro cadastro**. A aplicação tenta importar somente despesas manuais e cria um backup de segurança; o arquivo original não é apagado. Não copie arquivos de comparação nem bancos de terceiros. Se já criou a primeira conta, não crie uma segunda só para repetir a importação.

Não compartilhe `finance.sqlite`, `store.json`, backups ou exports financeiros: podem conter dados privados. Faça backups com o servidor encerrado.

**Atualização de uma versão anterior:** encerre o servidor antigo, faça uma cópia de segurança do banco e copie o arquivo `data\finance.sqlite` antigo para a pasta `data` da nova versão. Se seu projeto usa `DATABASE_PATH` personalizado, mantenha a mesma variável configurada para a versão nova. Se existir o arquivo `data\.registration-ip-hmac-secret` na instalação antiga, copie-o também para a pasta `data` da nova versão e mantenha-o protegido: ele mantém estável o contador pseudonimizado de cadastros por IP. Não o envie por chat nem o inclua em backups compartilhados. O ZIP não inclui bancos locais nem o segredo HMAC para não transportar dados privados/segredos.

## 7. Etapa atual do produto

Visitantes sem sessão veem uma Landing Page pública e acessam o login pelo botão Começar agora. A página usa apenas exemplos ilustrativos, nunca dados de clientes. Esta é uma aplicação local. O cadastro e login usam SQLite e sessões persistentes de até 30 dias. Há fluxos visuais demonstrativos de recuperação de senha e de segunda etapa no login, mas não existem envio real de e-mail, verificação real de OTP, integração bancária ou cobrança. A segunda etapa fictícia exige habilitação explícita no desenvolvimento (OVBECK_DEMO_2FA=1) e não é aceita em produção. A tela local de contratação Base/Premium existe, mas não processa cartões, não cria assinatura financeira e não cobra; CPF, número do cartão e CVV são validados no navegador e descartados antes de qualquer requisição. O acesso Premium local não é uma avaliação comercial cronometrada. Não é necessário HTTPS para acessar pelo endereço local `http://127.0.0.1`. Não exponha a porta local à internet. Documentos jurídicos precisam de revisão profissional antes de lançamento.


## Planos Base e Premium

O Básico é gratuito e permite despesas e recebimentos ilimitados e até cinco simulações salvas. Seu histórico pode ser consultado nos últimos seis meses; todos os registros mais antigos continuam armazenados. Existem quatro cotas mensais independentes, de três downloads cada: PDF de Despesas, Excel de Despesas, PDF de Histórico e Excel de Histórico. Os relatórios completos da Conta preservam cotas adicionais, independentes. O Premium, com preço comercial de R$ 29,90/mês, oferece histórico completo, simulações e exportações ilimitadas, até três contas vinculadas no total e personalização completa. A tela de contratação local existe. Para o Premium, CPF, cartão e CVV são validados por formato e descartados no navegador antes da requisição; não são armazenados nem enviados ao backend. Não há gateway, assinatura comercial ou cobrança real. A avaliação de sete dias e a primeira data de cobrança aparecem como informação de planejamento e não são um temporizador financeiro ativo.

Para fazer backup, execute `npm run db:backup`. Para restaurar, encerre o servidor e execute `npm run db:restore -- --source="caminho-do-backup.sqlite" --confirm-server-stopped`. A restauração cria uma cópia de segurança do banco atual.

## Navegação, foto e privacidade financeira

A barra lateral começa recolhida. Em computador, passe o mouse sobre ela para expandir; use o botão de fixação para mantê-la aberta. Em celular/tablet, use o botão de menu e feche o painel após navegar. O estado fixado é salvo por usuário neste dispositivo.

Em **Conta → Informações da conta**, os dados cadastrais disponíveis são somente para consulta. É possível adicionar, trocar ou remover uma foto de perfil. O backend valida e processa imagens estáticas JPEG, PNG, WebP, TIFF e AVIF; HEIC/HEIF dependem dos codecs disponíveis no Sharp instalado. BMP é convertido pelo navegador quando decodificável. O arquivo de origem tem limite técnico de 40 MB e 120 megapixels; a foto privada final é otimizada em JPEG 512×512. GIF, APNG, WebP animado, TIFF multipágina e arquivos que não sejam imagens são recusados. A exclusão da própria conta fica no fim de Informações da conta, exige a senha atual e mantém o tratamento assistido se houver histórico de cobrança que precise de retenção. Em **Conta → Renda mensal**, ficam renda, orçamento e downloads.

O botão de olho na barra superior oculta/mostra valores monetários globalmente, sem alterar cálculos, registros ou arquivos exportados. A preferência vale para navegação e recarga na mesma aba, mas uma nova autenticação começa com valores visíveis.

As migrações `020_profile_photos.sql` e `021_security_events_user_detach.sql` adicionam suporte à foto privada e permitem somente a desvinculação de eventos append-only na exclusão da conta. Antes de atualizar uma instalação com dados reais, faça backup de `data\finance.sqlite` e preserve o arquivo `data\.registration-ip-hmac-secret` se existir. O ZIP não leva banco, `.env` nem segredo local.

As logomarcas gráficas oficiais foram incorporadas aos PDFs e XLSX de Despesas, Histórico e exportação completa da Conta. A inspeção do website por navegador ainda requer conferência manual na sua instalação local, pois o Chromium deste ambiente foi bloqueado pela política de acesso aos endereços locais.

## Atualização da conta e fotos de perfil

A migração `020_profile_photos.sql` adiciona os campos privados da foto de perfil; `021_security_events_user_detach.sql` permite desvincular eventos de segurança da conta apagada, sem excluir a auditoria. Ambas são incrementais. Antes de atualizar uma instalação existente, faça backup de `data\finance.sqlite` e preserve `data\.registration-ip-hmac-secret` se existir.

Em **Conta → Informações da conta**, os dados cadastrais são somente para consulta, mas é possível adicionar, trocar ou remover a foto e solicitar a exclusão da própria conta. A exclusão exige a senha atual, bloqueia temporariamente após cinco falhas em 15 minutos e revoga as sessões. Caso exista histórico de cobrança sujeito a retenção, o sistema não o apaga automaticamente e direciona o pedido para atendimento assistido. Contas vinculadas de terceiros são desvinculadas sem excluir os outros usuários.

O processamento de fotos utiliza `sharp`/libvips no servidor. O arquivo de origem pode ter até 40 MB e 120 megapixels; a saída privada é otimizada em JPEG 512×512. São aceitos JPEG, PNG, WebP, TIFF e AVIF; HEIC/HEIF dependem dos codecs disponíveis na instalação. BMP é convertido no navegador quando decodificável. GIF, APNG, WebP animado, TIFF multipágina, vídeos, documentos, arquivos executáveis e imagens corrompidas são recusados. O instalador `INICIAR_OVBECK.bat` instala a dependência `sharp` declarada no `package.json` se ela estiver ausente (requer internet na primeira preparação).

O botão de olho mascara valores financeiros somente na apresentação, sem alterar o conteúdo dos campos, foco, cursor, cálculos, banco ou exportações. A preferência vale durante a mesma sessão/aba e é limpa no logout ou na nova autenticação.

A barra lateral começa recolhida, expande suavemente no desktop e permanece aberta durante a navegação enquanto o ponteiro estiver sobre ela; o usuário pode fixá-la. Em tablet/celular, use o botão de menu. A logomarca gráfica oficial está nas exportações PDF e XLSX de Despesas, Histórico e Conta.


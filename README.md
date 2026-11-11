# OVBECK — Plataforma de controle financeiro pessoal

Aplicação web local de controle financeiro pessoal com painel, despesas, histórico, recorrências, simulações de parcelas, exportações em PDF/Excel e gerenciamento administrativo. Esta distribuição mantém a identidade visual OVBECK. O fluxo inclui uma etapa local de contratação e confirmação de plano; não há autorização de cartão, gateway, assinatura comercial ou cobrança real.

> **Etapa local:** em `NODE_ENV=development`, o Premium pode ser habilitado na instalação local para permitir o uso e a validação dos recursos. Essa ativação local não cria assinatura, pagamento, renovação ou cobrança. A integração financeira será desenvolvida separadamente; não apresente o estado Premium local como pagamento efetuado.

## Funcionalidades presentes

- Cadastro em etapas, com validação de nome, e-mail e senha; a conta não é autenticada automaticamente.
- Login com senhas derivadas por scrypt e salt individual, sessões persistidas por hash, cookie `HttpOnly`, `SameSite=Strict`, proteção CSRF e sessão persistente.
- Proteção progressiva do login por conta e origem: cinco falhas consecutivas geram pausa de dez segundos; após a pausa, duas falhas adicionais provocam bloqueio temporário de uma hora. Login válido reinicia a contagem. Administradores autorizados podem liberar a conta com justificativa obrigatória.
- Limite separado de três contas concluídas por endereço IP, com liberação administrativa temporária e trilha de auditoria.
- Repetição de três envios inválidos com os mesmos dados no cadastro: o backend bloqueia novas tentativas daquele conjunto por janela temporária. A persistência utiliza HMAC do conteúdo normalizado, sem guardar os valores brutos ou a senha.
- Dashboard, despesas, recorrências, histórico, calculadora de parcelas, preferências financeiras, contas vinculadas, lixeira/recuperação, painel administrativo e log de auditoria.
- Exportações PDF e XLSX reais, com cotas mensais independentes no Básico e exportações ilimitadas no Premium.
- Indicadores numéricos e resumos por categoria com valores reais, sem gráficos nesta versão acadêmica.
- Seletor visual de contas vinculadas, com autenticação prévia de conta existente, confirmações e isolamento de dados.
- Recuperação de senha simulada na tela de login e em Informações da Conta, sem envio de e-mail.
- Opção demonstrativa de verificação em duas etapas protegida por `OVBECK_DEMO_2FA=1` em ambiente não produtivo. Em produção a opção não aceita códigos fictícios.
- Banco SQLite persistente com migrações SQL versionadas.
- Estrutura de dados e código de integração de pagamentos mantidos para uma etapa futura; a tela local não processa pagamento nem chama webhooks.
- Personalização Premium com seletor de cor contínuo, tonalidade, código hexadecimal, pré-visualização, salvamento individual e restauração do padrão.
- Sincronização entre sessões por revisão persistente no SQLite; clientes autenticados consultam a revisão e atualizam os dados sem recarregar a página.
- Backup SQLite validado por `PRAGMA integrity_check` e restauração com cópia de segurança automática do banco substituído.
- Painel administrativo com identificação de clientes, bloqueios, liberações, auditoria e estados de assinatura/pagamento existentes no banco.

## Planos

| Plano | Benefícios |
|---|---|
| Básico | Gratuito; despesas e recebimentos ilimitados; histórico dos últimos seis meses (dados antigos preservados); até cinco simulações salvas; mensalmente 3 PDFs de Despesas, 3 Excel de Despesas, 3 PDFs de Histórico e 3 Excel de Histórico, em cotas independentes. |
| Premium | R$ 29,90/mês; despesas, recebimentos, simulações e exportações ilimitados; histórico completo; análises avançadas, até três contas vinculadas no total e personalização visual avançada. |

A condição comercial planejada para o Premium é **R$ 29,90 por ciclo de 30 dias**, com **sete dias gratuitos quando houver contratação válida**. Nesta etapa local, o período comercial não é iniciado: não há contratação financeira nem cobrança; os recursos Premium podem ser habilitados localmente sem representar pagamento efetuado ou assinatura recorrente.

## Iniciar localmente

1. Use Node.js 22.16.0 ou superior.
2. Extraia o arquivo ZIP para uma pasta local.
3. No Windows, execute `INICIAR_OVBECK.bat`. Na primeira inicialização, o script instala automaticamente a dependência `sharp` declarada no `package.json` se ainda não estiver instalada; é necessária conexão com a internet nessa primeira preparação. Também é possível executar `npm install` manualmente na pasta do projeto.
4. O assistente administrativo continua sendo executado pelo inicializador antes do servidor. Na primeira inicialização, um assistente solicitará uma única vez o e-mail, o nome e a senha inicial do administrador. Use o e-mail configurado para sua conta administrativa e, conforme solicitado, pode definir `A1` como senha temporária local; a troca será obrigatória no primeiro login. A senha é digitada sem aparecer na tela e guardada somente em `.env`, arquivo ignorado pelo Git e excluído do ZIP.
5. Nas próximas inicializações, o assistente não pergunta novamente: o backend verifica e mantém a conta de forma idempotente. Para iniciar pelo terminal sem o `.bat`, execute `npm run admin:setup` uma única vez e depois `npm start`.
6. Acesse `http://127.0.0.1:4173` (ou o endereço exibido pelo servidor).

Não exponha o servidor local diretamente à internet. HTTPS e uma origem pública são pré-requisitos para habilitar o checkout.

## Acesso Premium na instalação local

O arquivo `.env.example` usa `NODE_ENV=development`. Nessa configuração, a instalação oferece ativação local dos recursos Premium por seleção do plano. Para desativar esse acesso local, defina `LOCAL_PREMIUM_ACCESS=0`. O formulário Premium mostra o período e a data estimada, mas o modo local não inicia uma avaliação comercial cronometrada, não consulta o Mercado Pago e não cria cobrança, transação paga ou assinatura recorrente. CPF, cartão e CVV ficam apenas no navegador, são validados por formato e apagados antes da requisição.

As variáveis `MP_ACCESS_TOKEN`, `MP_WEBHOOK_SECRET` e `MP_API_BASE_URL` são reservadas para uma etapa futura e permanecem vazias nesta entrega. Não configure credenciais de pagamento agora. A habilitação de pagamentos em produção exige uma implementação e homologação separadas, credenciais, domínio público e webhook seguro.

## Backup e restauração

Crie backup com o servidor aberto ou fechado:

```bash
npm run db:backup
```

O backup é gravado por padrão em `data/backups`, com permissão restrita e verificação de integridade. Para restaurar, encerre o servidor e execute:

```bash
npm run db:restore -- --source="data/backups/finance-AAAA-MM-DDTHH-MM-SS-sssZ.sqlite" --confirm-server-stopped
```

A restauração verifica o arquivo escolhido, cria uma cópia de segurança do banco atual e só então substitui o arquivo. Não interrompa a restauração. Proteja backups como dados financeiros pessoais; não os compartilhe.

## Migrações e dados existentes

As migrações estão em `migrations/` e são executadas pelo inicializador do banco. As migrações 015, 016 e 017 adicionam, respectivamente, proteção contra reenvios repetidos de cadastro inválido, preferências visuais e revisão de sincronização, e dados de endereço de cobrança e paletas independentes de superfícies. Nenhuma coluna armazena CPF, número de cartão ou CVV.

Faça backup do arquivo SQLite antes de atualizar uma instalação com dados reais. A aplicação não deve ser atualizada sobre uma cópia única do banco sem backup verificável.

## Segurança operacional

- Em produção, configure `NODE_ENV=production` e `APP_ORIGIN` para uma origem HTTPS pública.
- Defina `REGISTRATION_IP_HMAC_SECRET` com pelo menos 32 bytes aleatórios e guarde-o fora do código-fonte. Alterá-lo muda a capacidade de correlacionar fingerprints e IPs já registrados.
- Configure `TRUSTED_PROXY_IPS` somente com endereços dos proxies reversos que realmente controlam os cabeçalhos encaminhados. Não confie indiscriminadamente em `X-Forwarded-For`.
- Restrinja acesso ao arquivo SQLite e aos backups; não os sirva como arquivos estáticos.
- Mantenha `.env`, tokens, chaves, banco de dados, dados pessoais e arquivos de backup fora de commits e pacotes distribuídos.
- Antes de qualquer lançamento, configure backups automáticos, monitore falhas de webhook, teste restauração e revise termos e política de privacidade com base nas operações efetivamente ativadas.

## Validação automatizada

- `npm run check` — verifica sintaxe dos módulos e testes, incluindo backup, restauração e personalização Premium.
- `npm test` — executa testes unitários e de integração.
- `npm run stress` — executa 2.600 verificações repetidas dos fluxos críticos, em base isolada.
- `npm run stress:admin` — executa 100 ciclos administrativos, em base isolada.

A cobertura automatizada não substitui um teste de navegação em navegador real em todas as resoluções nem a homologação ponta a ponta no ambiente de testes do Mercado Pago.

## Refinamento de conta, fotos, privacidade e segurança — 09/11/2026

- A barra lateral permanece recolhida como padrão, expande por hover em desktop com transição de aproximadamente 320 ms e continua aberta durante navegação enquanto o ponteiro permanece sobre a área; a preferência fixada é persistida por conta/dispositivo. Em telas touch, o menu é aberto pelo botão de navegação.
- A logomarca da barra lateral usa um único símbolo gráfico; o estado expandido acrescenta o nome OVBECK sem duplicar a imagem.
- `Conta → Informações da conta` exibe os dados cadastrados somente para consulta, permite gerenciar a foto e oferece a ação de exclusão da própria conta com confirmação pela senha atual. Cinco confirmações inválidas em 15 minutos bloqueiam novas tentativas temporariamente. A exclusão remove sessões e dados vinculados, desassocia contas de terceiros sem apagá-las e respeita o tratamento assistido quando há histórico de cobrança que precise de retenção.
- Fotos de perfil estáticas são validadas e processadas no servidor com `sharp`/libvips. O limite técnico é 40 MB de arquivo de origem e 120 megapixels, com saída otimizada JPEG de 512×512. São aceitos JPEG, PNG, WebP, TIFF e AVIF, além de HEIC/HEIF quando o decoder HEIF da instalação os suportar. BMP é convertido para JPEG no navegador quando este consegue decodificá-lo. GIF, APNG, WebP animado, TIFF multipágina, vídeos, documentos, arquivos executáveis e conteúdo corrompido são recusados. A foto final é privada, vinculada ao usuário e nunca armazenada como conteúdo executável.
- O botão global de privacidade altera somente CSS e a camada de apresentação. Não muda `value`, tipo, foco ou seleção dos campos monetários; quando acionado a partir de um input, o foco e a posição do cursor são preservados. Cálculos e exportações continuam recebendo valores reais. O estado vale durante a mesma sessão/aba e é limpo em logout/nova autenticação.
- A migração `020_profile_photos.sql` adiciona os campos binários da foto sem apagar registros. A migração `021_security_events_user_detach.sql` mantém os eventos de segurança append-only, permitindo exclusivamente a desvinculação de `user_id` para NULL exigida pela FK quando a conta é excluída. Ambas são incrementais e não removem dados financeiros existentes.
- As exportações PDF e XLSX de Despesas, Histórico e Conta mantêm a logomarca gráfica oficial adequada ao fundo e dentro da área imprimível.

Para a inicialização, a instalação da dependência `sharp` é automática no primeiro uso do `INICIAR_OVBECK.bat` se estiver ausente (requer conexão com a internet); alternativamente, execute `npm install` manualmente.

A inspeção do website em navegador real permanece uma validação separada. Nesta execução, o navegador automatizado foi bloqueado por uma política da infraestrutura (`ERR_BLOCKED_BY_ADMINISTRATOR`) ao tentar abrir `127.0.0.1`. A inspeção visual das sete resoluções não pode ser considerada concluída. Testes de API, sintaxe, integração e contratos de UI não a substituem.

## Conta, privacidade e marca nas exportações

A barra lateral começa recolhida e expande por hover no desktop; em telas touch, use o botão de menu. O avatar da barra lateral abre o gerenciamento de contas. Em **Conta → Informações da conta**, os dados cadastrais disponíveis são apenas para consulta e a foto pode ser adicionada/trocada/removida. Em **Conta → Renda mensal**, permanecem renda, orçamento e downloads. O botão de olho no cabeçalho mascara valores em toda a área financeira sem alterar os dados nem as exportações; uma nova sessão começa com os valores visíveis.

As exportações de Despesas, Histórico e Conta incluem a logomarca oficial OVBECK nos formatos PDF e XLSX. Consulte `docs/RELATORIO-REFINAMENTO-FINAL-OVBECK-2026-11-08.md` para os testes e limitações desta etapa. A inspeção visual do website em navegador real ainda requer validação local.

Relatório técnico desta etapa: `docs/RELATORIO-REFINAMENTO-FINAL-OVBECK-2026-11-08.md`.

## Atualização integrada de 09/11/2026 — normas atuais

O Premium custa R$ 29,90/mês na proposta comercial, sem cobrança real habilitada nesta entrega. O Básico oferece recebimentos e despesas ilimitados, histórico dos últimos seis meses e quatro cotas mensais independentes de exportação. Os dados mais antigos não são excluídos do SQLite. Os relatórios completos da Conta, recurso legado preservado, mantêm suas próprias cotas independentes. O Premium oferece até três perfis no grupo, histórico completo, simulações e downloads ilimitados.

Para testar a verificação demonstrativa em duas etapas, defina `OVBECK_DEMO_2FA=1` no `.env` **somente em desenvolvimento**, reinicie a aplicação e habilite a preferência em Informações da Conta. Nesse modo, quaisquer seis números concluem a etapa visual após a senha correta; nenhum e-mail é enviado. Para implantação real, será necessária a verificação de segundo fator com código legítimo e expiração; o modo demonstrativo nunca deve ser promovido à produção.

As migrações até `022_optional_demo_second_step.sql` são executadas automaticamente ao iniciar. Faça backup da base existente antes de migrar. Um relatório da revisão, testes e limitações está em `docs/RELATORIO-AUDITORIA-INTEGRADA-2026-11-09.md`.

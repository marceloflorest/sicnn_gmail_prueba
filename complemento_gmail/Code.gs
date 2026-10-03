/**
 * COMPLEMENTO DE GMAIL - Detección de Phishing (SiCNN)
 */
const URL_SERVIDOR = "https://cash-politely-detector.ngrok-free.dev"; // URL de tu servidor ngrok

// --- Configuración de etiquetas y lotes ---
const NOMBRE_ETIQUETA_PHISHING = "SiCNN/PHISHING";
const NOMBRE_ETIQUETA_LEGITIMO = "SiCNN/LEGÍTIMO";
const TAMANO_LOTE = 50; // correos procesados por cada clic en "Analizar"

// --- Opciones del menú desplegable "Ubicación de Gmail" ---
// [ etiqueta visible , consulta de búsqueda de Gmail ]
const UBICACIONES_GMAIL = [
  ["Recibidos", "in:inbox"],
  ["Importantes", "is:important"],
  ["Todos", "in:anywhere"],
  ["Spam", "in:spam"],
  ["Enviados", "in:sent"],
  ["Compras", "category:purchases"],
  ["Promociones", "category:promotions"],
  ["Redes sociales", "category:social"],
  ["Actualizaciones", "category:updates"],
  ["Foros", "category:forums"],
];

function obtenerOCrearEtiqueta(nombre) {
  let etiqueta = GmailApp.getUserLabelByName(nombre);
  if (!etiqueta) {
    etiqueta = GmailApp.createLabel(nombre);
  }
  return etiqueta;
}

/**
 * Aplica la etiqueta correspondiente (PHISHING o LEGÍTIMO) al hilo de
 * un mensaje, según el resultado de la clasificación.
 */
function etiquetarMensaje(mensaje, clasificacion) {
  const etiqueta = clasificacion === "PHISHING"
    ? obtenerOCrearEtiqueta(NOMBRE_ETIQUETA_PHISHING)
    : obtenerOCrearEtiqueta(NOMBRE_ETIQUETA_LEGITIMO);
  mensaje.getThread().addLabel(etiqueta);
}

/**
 * Se ejecuta al abrir Gmail sin correo seleccionado (Bandeja de entrada).
 */
function alAbrirBandeja(e) {
  return [construirTarjetaPrincipal()];
}

/**
 * Construye la tarjeta principal: selector de ubicación + botón
 * Analizar + botón Descargar informe (siempre disponible, descarga el
 * acumulado completo de todo lo etiquetado hasta el momento).
 */
function construirTarjetaPrincipal() {
  const seccion = CardService.newCardSection().setHeader("Detección de correo");

  const dropdown = CardService.newSelectionInput()
    .setType(CardService.SelectionInputType.DROPDOWN)
    .setTitle("Ubicación de Gmail")
    .setFieldName("ubicacion");

  UBICACIONES_GMAIL.forEach((opcion, i) => {
    dropdown.addItem(opcion[0], opcion[1], i === 0);
  });
  seccion.addWidget(dropdown);

  const botonAnalizar = CardService.newTextButton()
    .setText("Analizar")
    .setOnClickAction(CardService.newAction().setFunctionName("analizarLote"));
  seccion.addWidget(botonAnalizar);

  const botonDescargar = CardService.newTextButton()
    .setText("Descargar informe en Excel")
    .setOpenLink(CardService.newOpenLink().setUrl(`${URL_SERVIDOR}/descargar-informe`));
  seccion.addWidget(botonDescargar);

  const card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Detección de Phishing"))
    .addSection(seccion);

  return card.build();
}

/**
 * Se ejecuta al abrir un correo electrónico específico. No requiere
 * cambios respecto a la versión anterior: sigue funcionando igual,
 * sin importar en qué carpeta esté el correo (bandeja, spam, etc.).
 */
function alAbrirCorreo(e) {
  const messageId = (e && e.gmail && e.gmail.messageId) ? e.gmail.messageId : null;

  const seccion = CardService.newCardSection().setHeader("Detección de correo");

  const accionAnalizar = CardService.newAction().setFunctionName("analizarCorreoActual");
  if (messageId) {
    accionAnalizar.setParameters({ messageId: String(messageId) });
  }

  const botonAnalizar = CardService.newTextButton()
    .setText("Analizar este correo")
    .setOnClickAction(accionAnalizar);
  seccion.addWidget(botonAnalizar);

  const botonDescargar = CardService.newTextButton()
    .setText("Descargar informe en Excel")
    .setOpenLink(CardService.newOpenLink().setUrl(`${URL_SERVIDOR}/descargar-informe`));
  seccion.addWidget(botonDescargar);

  const card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Detección de Phishing"))
    .addSection(seccion);

  return [card.build()];
}

/**
 * Analiza el siguiente lote de correos SIN etiquetar (hasta
 * TAMANO_LOTE), dentro de la ubicación elegida en el menú desplegable.
 * Cada clic procesa el siguiente lote -- los correos ya etiquetados en
 * clics anteriores se excluyen automáticamente de la búsqueda.
 */
function analizarLote(e) {
  const ubicacion = (e.formInput && e.formInput.ubicacion) ? e.formInput.ubicacion : "in:inbox";
  const consulta = `${ubicacion} -label:"${NOMBRE_ETIQUETA_PHISHING}" -label:"${NOMBRE_ETIQUETA_LEGITIMO}"`;

  const hilos = GmailApp.search(consulta, 0, TAMANO_LOTE);

  if (hilos.length === 0) {
    return construirTarjetaMensaje("No se encontraron correos nuevos por analizar en esta ubicación.");
  }

  const correos = [];
  const mapaMensajePorId = {};

  hilos.forEach((hilo) => {
    const mensajes = hilo.getMessages();
    const ultimo = mensajes[mensajes.length - 1];
    correos.push({
      id: ultimo.getId(),
      fecha_hora: Utilities.formatDate(ultimo.getDate(), Session.getScriptTimeZone(), "dd/MM/yyyy HH:mm"),
      asunto: ultimo.getSubject() || "",
      remitente: ultimo.getFrom() || "",
      texto_correo: ultimo.getPlainBody().substring(0, 3000),
    });
    mapaMensajePorId[ultimo.getId()] = ultimo;
  });

  const resultado = enviarCorreosAClasificar(correos);
  if (resultado.error) {
    return construirTarjetaError(resultado.error);
  }

  resultado.resultados.forEach((r) => {
    const mensaje = mapaMensajePorId[r.id];
    if (mensaje) {
      etiquetarMensaje(mensaje, r.clasificacion);
    }
  });

  const hayMas = hilos.length === TAMANO_LOTE;
  return construirTarjetaResultado(resultado, hayMas);
}

/**
 * Analiza solo el correo actualmente abierto.
 */
function analizarCorreoActual(e) {
  const messageId = e.parameters ? e.parameters.messageId : null;

  if (!messageId) {
    return construirTarjetaError("No se pudo obtener el ID del correo actual.");
  }

  const mensaje = GmailApp.getMessageById(messageId);

  const correo = {
    id: mensaje.getId(),
    fecha_hora: Utilities.formatDate(mensaje.getDate(), Session.getScriptTimeZone(), "dd/MM/yyyy HH:mm"),
    asunto: mensaje.getSubject() || "",
    remitente: mensaje.getFrom() || "",
    texto_correo: mensaje.getPlainBody().substring(0, 3000),
  };

  const resultado = enviarCorreosAClasificar([correo]);
  if (resultado.error) {
    return construirTarjetaError(resultado.error);
  }

  etiquetarMensaje(mensaje, resultado.resultados[0].clasificacion);

  return construirTarjetaResultado(resultado, false);
}

/**
 * Envía un lote de correos al backend Flask/ngrok para clasificar.
 * Devuelve { error } o { total, legitimos, phishing, resultados }.
 */
function enviarCorreosAClasificar(correos) {
  const opciones = {
    method: "post",
    contentType: "application/json",
    headers: { "ngrok-skip-browser-warning": "true" },
    payload: JSON.stringify({ correos: correos }),
    muteHttpExceptions: true,
  };

  try {
    const respuesta = UrlFetchApp.fetch(`${URL_SERVIDOR}/api/analizar`, opciones);
    const datos = JSON.parse(respuesta.getContentText());
    if (datos.error) {
      return { error: datos.error };
    }
    return datos;
  } catch (err) {
    return { error: "Error al conectar con el servidor ngrok: " + err.message };
  }
}

/**
 * Renderiza el resultado de un análisis (lote o correo individual).
 */
function construirTarjetaResultado(datos, hayMas) {
  const seccion = CardService.newCardSection().setHeader("Resultado del análisis");

  seccion.addWidget(
    CardService.newDecoratedText().setTopLabel("Total analizado").setText(String(datos.total))
  );
  seccion.addWidget(
    CardService.newDecoratedText().setTopLabel("Legítimos").setText(String(datos.legitimos))
  );
  seccion.addWidget(
    CardService.newDecoratedText().setTopLabel("Phishing").setText(String(datos.phishing))
  );

  if (datos.resultados && datos.resultados.length === 1) {
    const r = datos.resultados[0];
    seccion.addWidget(
      CardService.newDecoratedText()
        .setTopLabel("Clasificación")
        .setText(`${r.clasificacion} (${r.probabilidad_phishing}%)`)
    );
  }

  if (datos.blockchain) {
    seccion.addWidget(
      CardService.newDecoratedText()
        .setTopLabel("Registrado en Blockchain")
        .setText(`${datos.blockchain.bloques_creados} bloque(s) — ${datos.blockchain.cadena_valida ? "Cadena válida ✓" : "⚠ Cadena corrompida"}`)
    );
  }

  if (hayMas) {
    seccion.addWidget(
      CardService.newTextParagraph().setText(
        "<i>Hay más correos por analizar en esta ubicación. Presiona \"Analizar\" de nuevo para continuar con el siguiente lote.</i>"
      )
    );
  }

  const botonDescargar = CardService.newTextButton()
    .setText("Descargar informe en Excel")
    .setOpenLink(CardService.newOpenLink().setUrl(`${URL_SERVIDOR}/descargar-informe`));
  seccion.addWidget(botonDescargar);

  const botonVolver = CardService.newTextButton()
    .setText("Volver")
    .setOnClickAction(CardService.newAction().setFunctionName("volverATarjetaPrincipal"));
  seccion.addWidget(botonVolver);

  const card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Detección de Phishing"))
    .addSection(seccion);

  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(card.build()))
    .build();
}

function volverATarjetaPrincipal(e) {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(construirTarjetaPrincipal()))
    .build();
}

function construirTarjetaMensaje(mensaje) {
  const seccion = CardService.newCardSection();
  seccion.addWidget(CardService.newTextParagraph().setText(mensaje));

  const botonVolver = CardService.newTextButton()
    .setText("Volver")
    .setOnClickAction(CardService.newAction().setFunctionName("volverATarjetaPrincipal"));
  seccion.addWidget(botonVolver);

  const card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Detección de Phishing"))
    .addSection(seccion);

  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(card.build()))
    .build();
}

function construirTarjetaError(mensajeError) {
  const seccion = CardService.newCardSection().setHeader("Error");
  seccion.addWidget(CardService.newTextParagraph().setText(mensajeError));

  const botonVolver = CardService.newTextButton()
    .setText("Volver")
    .setOnClickAction(CardService.newAction().setFunctionName("volverATarjetaPrincipal"));
  seccion.addWidget(botonVolver);

  const card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Detección de Phishing"))
    .addSection(seccion);

  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(card.build()))
    .build();
}

// ============================================================
// ETIQUETADO AUTOMÁTICO EN SEGUNDO PLANO (opcional)
// ============================================================

const MINUTOS_ENTRE_REVISIONES = 15;

/**
 * Se ejecuta automáticamente cada MINUTOS_ENTRE_REVISIONES minutos
 * (una vez activado con activarAnalisisAutomatico). Revisa correos
 * nuevos sin etiqueta en bandeja de entrada y spam.
 */
function revisarYEtiquetarCorreosNuevos() {
  const consulta = `(in:inbox OR in:spam) -label:"${NOMBRE_ETIQUETA_PHISHING}" -label:"${NOMBRE_ETIQUETA_LEGITIMO}"`;
  const hilos = GmailApp.search(consulta, 0, TAMANO_LOTE);

  if (hilos.length === 0) {
    Logger.log("No hay correos nuevos por analizar.");
    return;
  }

  const correos = [];
  const mapaMensajePorId = {};

  hilos.forEach((hilo) => {
    const mensajes = hilo.getMessages();
    const ultimo = mensajes[mensajes.length - 1];
    correos.push({
      id: ultimo.getId(),
      fecha_hora: Utilities.formatDate(ultimo.getDate(), Session.getScriptTimeZone(), "dd/MM/yyyy HH:mm"),
      asunto: ultimo.getSubject() || "",
      remitente: ultimo.getFrom() || "",
      texto_correo: ultimo.getPlainBody().substring(0, 3000),
    });
    mapaMensajePorId[ultimo.getId()] = ultimo;
  });

  const resultado = enviarCorreosAClasificar(correos);
  if (resultado.error) {
    Logger.log("Error: " + resultado.error);
    return;
  }

  resultado.resultados.forEach((r) => {
    const mensaje = mapaMensajePorId[r.id];
    if (mensaje) {
      etiquetarMensaje(mensaje, r.clasificacion);
    }
  });

  Logger.log(`Se etiquetaron ${resultado.resultados.length} correos automáticamente.`);
}

function activarAnalisisAutomatico() {
  ScriptApp.getProjectTriggers().forEach((t) => {
    if (t.getHandlerFunction() === "revisarYEtiquetarCorreosNuevos") {
      ScriptApp.deleteTrigger(t);
    }
  });
  ScriptApp.newTrigger("revisarYEtiquetarCorreosNuevos")
    .timeBased()
    .everyMinutes(MINUTOS_ENTRE_REVISIONES)
    .create();
  Logger.log(`Análisis automático ACTIVADO: cada ${MINUTOS_ENTRE_REVISIONES} minutos.`);
}

function desactivarAnalisisAutomatico() {
  let eliminados = 0;
  ScriptApp.getProjectTriggers().forEach((t) => {
    if (t.getHandlerFunction() === "revisarYEtiquetarCorreosNuevos") {
      ScriptApp.deleteTrigger(t);
      eliminados++;
    }
  });
  Logger.log(`Análisis automático DESACTIVADO (${eliminados} disparador(es) eliminado(s)).`);
}

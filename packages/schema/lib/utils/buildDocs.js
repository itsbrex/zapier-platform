'use strict';

const util = require('util');

const _ = require('lodash');
const toc = require('markdown-toc');

const packageJson = require('../../package.json');
const links = require('./links');

const NO_DESCRIPTION = '_No description given._';
const COMBOS = ['anyOf', 'allOf', 'oneOf'];
const { SKIP_KEY } = require('../constants');
const hiddenRefs = [];

const walkSchemas = (InitSchema, callback) => {
  const recurse = (Schema, parents) => {
    parents = parents || [];
    callback(Schema, parents);
    Schema.dependencies.forEach((childSchema) => {
      const newParents = parents.concat([InitSchema]);
      recurse(childSchema, newParents);
    });
  };
  recurse(InitSchema);
};

const collectSchemas = (InitSchema) => {
  const schemas = {};
  walkSchemas(InitSchema, (Schema) => {
    if (!_.get(Schema, 'schema.docAnnotation.hide')) {
      schemas[Schema.id] = Schema;
    } else {
      hiddenRefs.push(Schema.id);
    }
  });
  return schemas;
};

const BREAK_LENGTH = 96;
const prepQuote = (val) => val.replace('`', '');
const quote = (val, triple, indent = '') =>
  // either ``` with optional indentation or `
  triple && val.length > BREAK_LENGTH
    ? '```\n' +
      val
        .match(/[^\r\n]+/g)
        .map((line) => indent + line)
        .join('\n') +
      '\n' +
      indent +
      '```'
    : `\`${prepQuote(val)}\``;
const quoteOrNa = (val, triple = false, indent = '') =>
  val ? quote(val, triple, indent) : '_n/a_';

const formatExample = (example) => {
  const ex = _.isPlainObject(example) ? _.omit(example, SKIP_KEY) : example;
  return `* ${quoteOrNa(
    util.inspect(ex, { depth: null, breakLength: BREAK_LENGTH }),
    true,
    '  ',
  )}`.replace(/\s+\n/gm, '\n');
};

// Generate a display of the type (or link to a $ref).
const typeOrLink = (schema) => {
  if (schema.type === 'array' && schema.items) {
    return `${quoteOrNa(schema.type)}[${typeOrLink(schema.items)}]`;
  }
  if (schema.$ref) {
    if (!hiddenRefs.includes(schema.$ref)) {
      return `[${schema.$ref}](${links.anchor(schema.$ref)})`;
    }
    return;
  }
  for (let i = 0; i < COMBOS.length; i++) {
    const key = COMBOS[i];
    if (schema[key] && schema[key].length) {
      return `${key}(${schema[key]
        .map(typeOrLink)
        .filter(Boolean)
        .join(', ')})`;
    }
  }
  if (schema.enum && schema.enum.length) {
    return `${quoteOrNa(schema.type)} in (${schema.enum
      .map(util.inspect)
      .map(quoteOrNa)
      .join(', ')})`;
  }
  return quoteOrNa(schema.type);
};

// Properly quote and display examples.
const makeExampleSection = (Schema) => {
  const examples = Schema.schema.examples || [];
  if (!examples.length) {
    return '';
  }
  return `\
#### Examples

${examples.map(formatExample).join('\n')}
`;
};

// Properly quote and display anti-examples.
const makeAntiExampleSection = (Schema) => {
  const antiExamples = Schema.schema.antiExamples || [];
  if (!antiExamples.length) {
    return '';
  }
  return `\
#### Anti-Examples

${antiExamples
  .map(({ example, reason }) => {
    const formattedAntiExample = formatExample(example);
    // If block quote, newline and indent the reason.
    // Otherwise, show the reason inline w/ the anti-example and separated by a dash.
    return formattedAntiExample.endsWith('```')
      ? `${formattedAntiExample}\n  _${reason}_`
      : `${formattedAntiExample} - _${reason}_`;
  })
  .join('\n')}
`;
};

const processProperty = (key, property, propIsRequired) => {
  let isRequired = propIsRequired ? '**yes**' : 'no';
  if (_.get(property, 'docAnnotation.hide')) {
    return '';
  } else if (_.get(property, 'docAnnotation.required')) {
    // can also support keys besides "required"
    const annotation = property.docAnnotation.required;
    if (annotation.type === 'replace') {
      isRequired = annotation.value;
    } else if (annotation.type === 'append') {
      isRequired += annotation.value;
    } else {
      throw new Error(`unrecognized docAnnotation type: ${annotation.type}`);
    }
  }
  return `${quoteOrNa(key)} | ${isRequired} | ${typeOrLink(property)} | ${
    property.description || NO_DESCRIPTION
  }`;
};

// Enumerate the properties as a table.
const makePropertiesSection = (Schema) => {
  const properties =
    Schema.schema.properties || Schema.schema.patternProperties || {};
  if (!Object.keys(properties).length) {
    return '';
  }
  const required = Schema.schema.required || [];
  return `\
#### Properties

Key | Required | Type | Description
--- | -------- | ---- | -----------
${Object.keys(properties)
  .map((key) => {
    const property = properties[key];
    return processProperty(key, property, required.includes(key));
  })
  .join('\n')}
`;
};

// Given a "root" schema, create some markdown.
const makeMarkdownSection = (Schema) => {
  return `\
## ${Schema.id}

${Schema.schema.description || NO_DESCRIPTION}

#### Details

* **Type** - ${typeOrLink(Schema.schema)}${
    Schema.schema.pattern
      ? `
* **Pattern** - ${quoteOrNa(Schema.schema.pattern)}`
      : ''
  }
* [**Source Code**](${links.makeCodeLink(Schema.id)})

${makePropertiesSection(Schema)}
${makeExampleSection(Schema)}
${makeAntiExampleSection(Schema)}
`.trim();
};

// Generate the final markdown.
const buildDocs = (InitSchema) => {
  const schemas = collectSchemas(InitSchema);
  const markdownSections = _.chain(schemas)
    .values()
    .sortBy('id')
    .map(makeMarkdownSection)
    .join('\n\n-----\n\n');
  const docs = `\
<!-- {% raw %} -->
# \`zapier-platform-schema\` Generated Documentation

This is automatically generated by the \`npm run docs\` command in \`zapier-platform-schema\` version ${quoteOrNa(
    packageJson.version,
  )}.

-----

## Index
<!-- toc -->

-----

${markdownSections}
<!-- {% endraw %} -->
`.trim();
  return toc.insert(docs, { maxdepth: 2, bullets: '*' });
};

module.exports = buildDocs;

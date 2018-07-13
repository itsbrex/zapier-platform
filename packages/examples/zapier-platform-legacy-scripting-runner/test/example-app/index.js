const legacyScriptingSource = `
    var Zap = {
      get_session_info: function(bundle) {
        var encodedCredentials = btoa(bundle.auth_fields.username + ':' + bundle.auth_fields.password);
        var response = z.request({
          method: 'GET',
          headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json',
              'Authorization': 'Basic ' + encodedCredentials
          },
          url: 'https://auth-json-server.zapier.ninja/me'
        });

        if (response.status_code !== 200) {
          throw new HaltedException('Auth failed: ' + response.content);
        }

        // Endpoint /me doesn't really give us an API key. We're just
        // simulating username/password login in exchange of an API key here.
        return {
          key1: 'sec',
          key2: 'ret'
        };
      },

      pre_oauthv2_token: function(bundle) {
        bundle.request.url += 'token';
        return bundle.request;
      },

      post_oauthv2_token: function(bundle) {
        var data = z.JSON.parse(bundle.response.content);
        data.something_custom += '!!';
        data.name = 'Jane Doe';
        return data;
      },

      pre_oauthv2_refresh: function(bundle) {
        bundle.request.url += 'token';
        return bundle.request;
      },

      get_connection_label: function(bundle) {
        return 'Hi ' + bundle.test_result.name;
      },

      /*
       * Polling Trigger
       */

      contact_full_poll: function(bundle) {
        bundle.request.url = 'https://auth-json-server.zapier.ninja/users';
        var response = z.request(bundle.request);
        var contacts = z.JSON.parse(response.content);
        contacts[0].name = 'Patched by KEY_poll!';
        return contacts;
      },

      contact_full_pre_custom_trigger_fields: function(bundle) {
        bundle.request.url += 's';
        return bundle.request;
      },

      contact_full_post_custom_trigger_fields: function(bundle) {
        var fields = z.JSON.parse(bundle.response.content);
        fields.push({
          key: 'spin',
          label: 'Spin',
          type: 'string'
        });
        return fields;
      },

      contact_pre_pre_poll: function(bundle) {
        bundle.request.url = 'https://auth-json-server.zapier.ninja/users';
        bundle.request.params.id = 3;
        return bundle.request;
      },

      contact_post_post_poll: function(bundle) {
        var contacts = z.JSON.parse(bundle.response.content);
        contacts[0].name = 'Patched by KEY_post_poll!';
        return contacts;
      },

      contact_pre_post_pre_poll: function(bundle) {
        bundle.request.url = 'https://auth-json-server.zapier.ninja/users';
        bundle.request.params.id = 4;
        return bundle.request;
      },

      contact_pre_post_post_poll: function(bundle) {
        var contacts = z.JSON.parse(bundle.response.content);
        contacts[0].name = 'Patched by KEY_pre_poll & KEY_post_poll!';
        return contacts;
      },

      /*
       * Hook Trigger
       */

      // To be replaced to 'contact_hook_scripting_catch_hook' at runtime
      contact_hook_scripting_catch_hook_returning_object: function(bundle) {
        var result = bundle.cleaned_request;
        result.luckyNumber = 777;
        return result;
      },

      // To be replaced to 'contact_hook_scripting_catch_hook' at runtime
      contact_hook_scripting_catch_hook_returning_array: function(bundle) {
        var results = bundle.cleaned_request;
        for (const contact of results) {
          contact.luckyNumber = contact.id * 10;
        }
        return results;
      },

      // To be replaced with 'contact_hook_scripting_pre_hook' at runtime to enable
      contact_hook_scripting_pre_hook_disabled: function(bundle) {
        bundle.request.url = bundle.request.url.replace('/users/', '/movies/');
        return bundle.request;
      },

      // To be replaced with 'contact_hook_scripting_post_hook' at runtime to enable
      contact_hook_scripting_post_hook_returning_object: function(bundle) {
        var thing = z.JSON.parse(bundle.response.content);
        thing.year = 2018;
        return thing;
      },

      // To be replaced with 'contact_hook_scripting_post_hook' at runtime to enable
      contact_hook_scripting_post_hook_returning_array: function(bundle) {
        var thing = z.JSON.parse(bundle.response.content);
        thing.year = 2017;

        var anotherThing = {
          id: 5555,
          name: 'The Thing',
          year: 2016
        };

        return [thing, anotherThing];
      },

      pre_subscribe: function(bundle) {
        var data = z.JSON.parse(bundle.request.data);
        data.hidden_message = 'pre_subscribe was here!';
        bundle.request.data = z.JSON.stringify(data);
        return bundle.request;
      },

      post_subscribe: function(bundle) {
        // This will go to bundle.subscribe_data in pre_unsubscribe
        var data = z.JSON.parse(bundle.response.content);
        data.hiddenMessage = 'post_subscribe was here!';
        return data;
      },

      pre_unsubscribe: function(bundle) {
        var data = z.JSON.parse(bundle.request.data);
        data.hidden_message = 'pre_unsubscribe was here!';
        bundle.request.data = z.JSON.stringify(data);
        bundle.request.method = 'DELETE';
        return bundle.request;
      },

      /*
       * Create/Action
       */

      // To be replaced with 'movie_pre_write' at runtime
      movie_pre_write_disabled: function(bundle) {
        bundle.request.url += 's';
        bundle.request.data = z.JSON.stringify(bundle.action_fields_full);
        return bundle.request;
      },

      // To be replaced with 'movie_post_write' at runtime
      movie_post_write_disabled: function(bundle) {
        var data = z.JSON.parse(bundle.response.content);
        data.year = 2017;
        return data;
      },

      // To be replaced with 'movie_write' at runtime
      movie_write_sync: function(bundle) {
        bundle.request.url += 's';
        bundle.request.data = z.JSON.stringify(bundle.action_fields_full);
        var response = z.request(bundle.request);
        var data = z.JSON.parse(response.content);
        data.year = 2016;
        return data;
      },

      // To be replaced with 'movie_write' at runtime
      movie_write_async: function(bundle, callback) {
        bundle.request.url += 's';
        bundle.request.data = z.JSON.stringify(bundle.action_fields_full);
        z.request(bundle.request, function(err, response) {
          if (err) {
            callback(err, response);
          } else {
            var data = z.JSON.parse(response.content);
            data.year = 2015;
            callback(err, data);
          }
        });
      },

      // To be replaced with 'movie_pre_custom_action_fields' at runtime
      movie_pre_custom_action_fields_disabled: function(bundle) {
        bundle.request.url += 's';
        return bundle.request;
      },

      // To be replaced with 'movie_post_custom_action_fields' at runtime
      movie_post_custom_action_fields_disabled: function(bundle) {
        var fields = z.JSON.parse(bundle.response.content);
        fields.push({
          key: 'year',
          label: 'Year',
          type: 'int'
        });
        return fields;
      },

      // To be replaced with 'movie_custom_action_fields' at runtime
      movie_custom_action_fields_disabled: function(bundle) {
        // bundle.request.url should be an empty string to start with
        bundle.request.url += 'https://auth-json-server.zapier.ninja/input-fields';
        var response = z.request(bundle.request);
        var fields = z.JSON.parse(response.content);
        fields.push({
          key: 'year',
          label: 'Year',
          type: 'int'
        });
        return fields;
      },

      // To be replaced with 'movie_pre_custom_action_result_fields' at runtime
      movie_pre_custom_action_result_fields_disabled: function(bundle) {
        bundle.request.url += 's';
        return bundle.request;
      },

      // To be replaced with 'movie_post_custom_action_result_fields' at runtime
      movie_post_custom_action_result_fields_disabled: function(bundle) {
        var fields = z.JSON.parse(bundle.response.content);
        fields.push({
          key: 'tagline',
          label: 'Tagline',
          type: 'unicode'
        });
        return fields;
      },

      // To be replaced with 'movie_custom_action_result_fields' at runtime
      movie_custom_action_result_fields_disabled: function(bundle, callback) {
        // bundle.request.url should be an empty string to start with
        bundle.request.url += 'https://auth-json-server.zapier.ninja/output-fields';
        z.request(bundle.request, function(err, response) {
          if (err) {
            callback(err, response);
          } else {
            var fields = z.JSON.parse(response.content);
            fields.push({
              key: 'tagline',
              label: 'Tagline',
              type: 'unicode'
            });
            callback(err, fields);
          }
        });
      },

      /*
       * Search
       */

      // To be replaced with 'movie_pre_custom_search_fields' at runtime
      movie_pre_custom_search_fields_disabled: function(bundle) {
        bundle.request.url += 's';
        return bundle.request;
      },

      // To be replaced with 'movie_post_custom_search_fields' at runtime
      movie_post_custom_search_fields_disabled: function(bundle) {
        var fields = z.JSON.parse(bundle.response.content);
        fields.push({
          key: 'year',
          label: 'Year',
          type: 'int'
        });
        return fields;
      },

      // To be replaced with 'movie_custom_search_fields' at runtime
      movie_custom_search_fields_disabled: function(bundle) {
        // bundle.request.url should be an empty string to start with
        bundle.request.url += 'https://auth-json-server.zapier.ninja/input-fields';
        var response = z.request(bundle.request);
        var fields = z.JSON.parse(response.content);
        fields.push({
          key: 'year',
          label: 'Year',
          type: 'int'
        });
        return fields;
      },

      // To be replaced with 'movie_pre_custom_search_result_fields' at runtime
      movie_pre_custom_search_result_fields_disabled: function(bundle) {
        bundle.request.url += 's';
        return bundle.request;
      },

      // To be replaced with 'movie_post_custom_search_result_fields' at runtime
      movie_post_custom_search_result_fields_disabled: function(bundle) {
        var fields = z.JSON.parse(bundle.response.content);
        fields.push({
          key: 'tagline',
          label: 'Tagline',
          type: 'unicode'
        });
        return fields;
      },

      // To be replaced with 'movie_custom_search_result_fields' at runtime
      movie_custom_search_result_fields_disabled: function(bundle, callback) {
        // bundle.request.url should be an empty string to start with
        bundle.request.url += 'https://auth-json-server.zapier.ninja/output-fields';
        z.request(bundle.request, function(err, response) {
          if (err) {
            callback(err, response);
          } else {
            var fields = z.JSON.parse(response.content);
            fields.push({
              key: 'tagline',
              label: 'Tagline',
              type: 'unicode'
            });
            callback(err, fields);
          }
        });
      }
    };
`;

const ContactTrigger_full = {
  key: 'contact_full',
  noun: 'Contact',
  display: {
    label: 'New Contact with Full Scripting'
  },
  operation: {
    perform: {
      source: "return z.legacyScripting.run(bundle, 'trigger', 'contact_full');"
    },
    outputFields: [
      {
        key: 'id',
        label: 'ID',
        type: 'integer'
      },
      {
        key: 'name',
        label: 'Name',
        type: 'string'
      },
      {
        source:
          "return z.legacyScripting.run(bundle, 'trigger.output', 'contact_full');"
      }
    ],
    legacyProperties: {
      // Misses an 's' at the end on purpose for KEY_pre_custom_trigger_fields
      // to fix
      outputFieldsUrl: 'https://auth-json-server.zapier.ninja/output-field'
    }
  }
};

const ContactTrigger_pre = {
  key: 'contact_pre',
  noun: 'Contact',
  display: {
    label: 'New Contact with Pre Scripting'
  },
  operation: {
    perform: {
      source: "return z.legacyScripting.run(bundle, 'trigger', 'contact_pre');"
    }
  }
};

const ContactTrigger_post = {
  key: 'contact_post',
  noun: 'Contact',
  display: {
    label: 'New Contact with Post Scripting'
  },
  operation: {
    legacyProperties: {
      url: 'https://auth-json-server.zapier.ninja/users'
    },
    perform: {
      source: "return z.legacyScripting.run(bundle, 'trigger', 'contact_post');"
    }
  }
};

const ContactTrigger_pre_post = {
  key: 'contact_pre_post',
  noun: 'Contact',
  display: {
    label: 'New Contact with Pre & Post Scripting'
  },
  operation: {
    perform: {
      source:
        "return z.legacyScripting.run(bundle, 'trigger', 'contact_pre_post');"
    }
  }
};

const ContactHook_scriptingless = {
  key: 'contact_hook_scriptingless',
  noun: 'Contact',
  display: {
    label: 'Contact Hook without Scripting'
  },
  operation: {
    perform: {
      source:
        "return z.legacyScripting.run(bundle, 'trigger.hook', 'contact_hook_scriptingless');"
    }
  }
};

const ContactHook_scripting = {
  key: 'contact_hook_scripting',
  noun: 'Contact',
  display: {
    label: 'Contact Hook with KEY_catch_hook Scripting'
  },
  operation: {
    perform: {
      source:
        "return z.legacyScripting.run(bundle, 'trigger.hook', 'contact_hook_scripting');"
    },
    performSubscribe: {
      source:
        "return z.legacyScripting.run(bundle, 'trigger.hook.subscribe', 'contact_hook_scripting');"
    },
    performUnsubscribe: {
      source:
        "return z.legacyScripting.run(bundle, 'trigger.hook.unsubscribe', 'contact_hook_scripting');"
    },
    legacyProperties: {
      event: 'contact.created',
      hookType: 'rest'
    }
  }
};

const TestTrigger = {
  key: 'test',
  display: {
    label: 'Test Auth'
  },
  operation: {
    perform: {
      source: "return z.legacyScripting.run(bundle, 'trigger', 'test');"
    },
    legacyProperties: {
      url: 'https://auth-json-server.zapier.ninja/me'
    }
  }
};

const MovieCreate = {
  key: 'movie',
  noun: 'Movie',
  display: {
    label: 'Create a Movie'
  },
  operation: {
    perform: {
      source: "return z.legacyScripting.run(bundle, 'create', 'movie');"
    },
    inputFields: [
      { key: 'title', label: 'Title', type: 'string' },
      { key: 'genre', label: 'Genre', type: 'string' },
      {
        source: "return z.legacyScripting.run(bundle, 'create.input', 'movie');"
      }
    ],
    outputFields: [
      { key: 'id', label: 'ID', type: 'integer' },
      { key: 'title', label: 'Title', type: 'string' },
      { key: 'genre', label: 'Genre', type: 'string' },
      {
        source:
          "return z.legacyScripting.run(bundle, 'create.output', 'movie');"
      }
    ],
    legacyProperties: {
      // The URLs miss an 's' at the end on purpose for scripting to fix it
      url: 'https://auth-json-server.zapier.ninja/movie',
      inputFieldsUrl: 'https://auth-json-server.zapier.ninja/input-field',
      outputFieldsUrl: 'https://auth-json-server.zapier.ninja/output-field',
      fieldsExcludedFromBody: ['title']
    }
  }
};

const MovieSearch = {
  key: 'movie',
  noun: 'Movie',
  display: {
    label: 'Find a Movie'
  },
  operation: {
    perform: {
      source: "return z.legacyScripting.run(bundle, 'search', 'movie');"
    },
    inputFields: [
      { key: 'title', label: 'Title', type: 'string' },
      {
        source: "return z.legacyScripting.run(bundle, 'search.input', 'movie');"
      }
    ],
    outputFields: [
      { key: 'id', label: 'ID', type: 'integer' },
      { key: 'title', label: 'Title', type: 'string' },
      { key: 'genre', label: 'Genre', type: 'string' },
      {
        source:
          "return z.legacyScripting.run(bundle, 'search.output', 'movie');"
      }
    ],
    legacyProperties: {
      // The URLs miss an 's' at the end on purpose for scripting to fix it
      url: 'https://auth-json-server.zapier.ninja/movie',
      inputFieldsUrl: 'https://auth-json-server.zapier.ninja/input-field',
      outputFieldsUrl: 'https://auth-json-server.zapier.ninja/output-field'
    }
  }
};

const App = {
  title: 'Example App',
  triggers: {
    [ContactTrigger_full.key]: ContactTrigger_full,
    [ContactTrigger_pre.key]: ContactTrigger_pre,
    [ContactTrigger_post.key]: ContactTrigger_post,
    [ContactTrigger_pre_post.key]: ContactTrigger_pre_post,
    [ContactHook_scriptingless.key]: ContactHook_scriptingless,
    [ContactHook_scripting.key]: ContactHook_scripting,
    [TestTrigger.key]: TestTrigger
  },
  creates: {
    [MovieCreate.key]: MovieCreate
  },
  searches: {
    [MovieSearch.key]: MovieSearch
  },
  legacyProperties: {
    subscribeUrl: 'http://zapier-httpbin.herokuapp.com/post',
    unsubscribeUrl: 'https://zapier-httpbin.herokuapp.com/delete'
  },
  legacyScriptingSource
};

module.exports = App;
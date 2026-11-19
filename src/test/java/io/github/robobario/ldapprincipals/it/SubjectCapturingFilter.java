package io.github.robobario.ldapprincipals.it;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.stream.Collectors;

import io.kroxylicious.kafka.common.message.RequestHeaderData;
import io.kroxylicious.kafka.common.protocol.ApiKeys;
import io.kroxylicious.kafka.common.protocol.ApiMessage;
import io.kroxylicious.proxy.authentication.Principal;
import io.kroxylicious.proxy.filter.FilterContext;
import io.kroxylicious.proxy.filter.RequestFilter;
import io.kroxylicious.proxy.filter.RequestFilterResult;

/**
 * Test-only filter: captures the authenticated subject of every request onto a static queue
 * so an IT running in the same JVM as the proxy can observe it, without needing to smuggle
 * it through the Kafka wire protocol.
 */
public class SubjectCapturingFilter implements RequestFilter {

    static final BlockingQueue<String> CAPTURED_SUBJECTS = new LinkedBlockingQueue<>();

    @Override
    public CompletionStage<RequestFilterResult> onRequest(ApiKeys apiKey,
                                                           short apiVersion,
                                                           RequestHeaderData header,
                                                           ApiMessage request,
                                                           FilterContext context) {
        var subject = context.authenticatedSubject();
        if (!subject.principals().isEmpty()) {
            CAPTURED_SUBJECTS.offer(subject.principals().stream()
                    .map(Principal::toString)
                    .sorted()
                    .collect(Collectors.joining("|")));
        }
        return context.forwardRequest(header, request);
    }
}

package org.simplejavamail.internal.modules;

import org.simplejavamail.MailException;
import org.simplejavamail.api.email.EmailStartingBuilder;
import org.simplejavamail.api.internal.outlooksupport.model.EmailFromOutlookMessage;

import javax.annotation.Nonnull;
import java.io.File;
import java.io.InputStream;

public interface OutlookModule {
	/** @throws MailException wrapping exceptions from {@code org.simplejavamail.outlookmessageparser.OutlookMessageParser#parseMsg(File)}. */
	EmailFromOutlookMessage outlookMsgToEmailBuilder(@Nonnull final File msgFile, @Nonnull EmailStartingBuilder emailStartingBuilder) throws MailException;
	/** @throws MailException wrapping exceptions from {@code org.simplejavamail.outlookmessageparser.OutlookMessageParser#parseMsg(String)}. */
	EmailFromOutlookMessage outlookMsgToEmailBuilder(@Nonnull final String msgData, @Nonnull EmailStartingBuilder emailStartingBuilder) throws MailException;
	/** @throws MailException wrapping exceptions from {@code org.simplejavamail.outlookmessageparser.OutlookMessageParser#parseMsg(InputStream)}. */
	EmailFromOutlookMessage outlookMsgToEmailBuilder(@Nonnull final InputStream msgInputStream, @Nonnull EmailStartingBuilder emailStartingBuilder) throws MailException;
}
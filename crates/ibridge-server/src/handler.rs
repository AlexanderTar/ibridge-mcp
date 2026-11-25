// SPDX-License-Identifier: Apache-2.0

//! Server handler. One server is one account, with at most four tool calls in flight.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ibridge_core::{
    CalendarProvider, ContactsProvider, CoreError, Draft, FlagChange, MailSearch, Mailbox,
    MailboxPath, MailboxRole, Message, MessageId, MessageSummary, RemindersProvider, Unsubscribe,
    UnsubscribeMethod, decode, encode,
};
use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, ErrorData, Tool};
use rmcp::{ServerHandler, tool, tool_handler, tool_router};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::account::{AccountSnapshot, ServiceStatus};
use crate::calendar_tools::{CALENDAR_TOOLS, CALENDAR_WRITE_TOOLS, NoCalendar};
use crate::contacts_tools::{CONTACTS_TOOLS, CONTACTS_WRITE_TOOLS, NoContacts};
use crate::dto::{
    AccountStatusOut, AttachmentInfoOut, AttachmentOut, FlagParams, FlagsOut, GetAttachmentParams,
    GetMessageParams, IdOut, MailboxListOut, MailboxOut, MessageOut, MoveOut, MoveParams,
    SaveAttachmentParams, SavedAttachmentOut, SearchHitOut, SearchOut, SearchParams, SendOut,
    SendParams, ServiceOut, ServiceState, UnsubscribeMethodOut, UnsubscribeOut, UnsubscribeParams,
    UnsubscribeStatus, UnsubscribedOut,
};
use crate::error_map::{MappedError, map_core_error};
use crate::mail_api::{MailApi, MailDest, Unsubscribed};
use crate::sanitize::strip_hidden;
use crate::save::{safe_name, save_unique};

const MAX_IN_FLIGHT: usize = 4;
const DEFAULT_LIMIT: u32 = 25;
const MAX_LIMIT: u32 = 100;
const SENT_COPY_WARNING: &str = "sent, but the copy was not saved to Sent Messages";
const LINK_ONLY_NOTE: &str = "The sender offers only a web link. One-click unsubscribe is not available yet, so nothing was sent. The link is as the sender wrote it; open it in a browser to unsubscribe.";
const SAVE_ATTACHMENT: &str = "mail_save_attachment";
const MAIL_TOOLS: &[&str] = &[
    "mail_create_draft",
    "mail_get_attachment",
    "mail_get_message",
    "mail_list_mailboxes",
    "mail_move",
    "mail_save_attachment",
    "mail_search",
    "mail_send",
    "mail_set_flags",
    "mail_unsubscribe",
];
const WRITE_TOOLS: &[&str] = &[
    "mail_create_draft",
    "mail_move",
    "mail_save_attachment",
    "mail_send",
    "mail_set_flags",
    "mail_unsubscribe",
];

macro_rules! try_mail {
    ($call:expr) => {
        match $call {
            Ok(value) => value,
            Err(error) => return mapped(&error),
        }
    };
}

/// Whether a service's tools are in the tool list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tools {
    /// The tools are listed.
    Shown,
    /// The tools are hidden.
    Hidden,
}

/// Which services' tools are listed, and where saved attachments go.
#[derive(Debug, Clone)]
struct Tools3 {
    mail: Tools,
    calendar: Tools,
    contacts: Tools,
    downloads: Option<Arc<Path>>,
}

/// Who may call write tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    /// Write tools are hidden and rejected.
    ReadOnly,
    /// Read and write tools are available.
    ReadWrite,
}

/// MCP server for one account.
///
/// At most four tool calls run at once. A read-only server omits write tools
/// from the tool list and rejects a direct write call. Calendar and reminders
/// tools appear once [`IbridgeServer::with_calendar`] gives the server a backend,
/// and contacts tools once [`IbridgeServer::with_contacts`] does.
pub struct IbridgeServer<M, C = NoCalendar, K = NoContacts> {
    access: Access,
    account: AccountSnapshot,
    mail: Arc<M>,
    pub(crate) calendar: Arc<C>,
    pub(crate) contacts: Arc<K>,
    mail_tools: Tools,
    calendar_tools: Tools,
    contacts_tools: Tools,
    downloads: Option<Arc<Path>>,
    gate: Arc<Semaphore>,
    router: ToolRouter<Self>,
}

impl<M, C, K> fmt::Debug for IbridgeServer<M, C, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IbridgeServer")
            .field("access", &self.access)
            .field("account", &self.account)
            .finish_non_exhaustive()
    }
}

impl<M, C, K> Clone for IbridgeServer<M, C, K> {
    fn clone(&self) -> Self {
        Self {
            access: self.access,
            account: self.account.clone(),
            mail: Arc::clone(&self.mail),
            calendar: Arc::clone(&self.calendar),
            contacts: Arc::clone(&self.contacts),
            mail_tools: self.mail_tools,
            calendar_tools: self.calendar_tools,
            contacts_tools: self.contacts_tools,
            downloads: self.downloads.clone(),
            gate: Arc::clone(&self.gate),
            router: self.router.clone(),
        }
    }
}

impl<M> IbridgeServer<M, NoCalendar, NoContacts>
where
    M: MailApi + Send + Sync + 'static,
{
    /// Hides write tools from the tool list and rejects write calls.
    #[must_use]
    pub fn read_only(account: AccountSnapshot, mail: Arc<M>) -> Self {
        Self::build(
            Access::ReadOnly,
            account,
            mail,
            Arc::new(NoCalendar),
            Arc::new(NoContacts),
        )
    }

    /// Shows read and write tools.
    #[must_use]
    pub fn read_write(account: AccountSnapshot, mail: Arc<M>) -> Self {
        Self::build(
            Access::ReadWrite,
            account,
            mail,
            Arc::new(NoCalendar),
            Arc::new(NoContacts),
        )
    }
}

impl<M, C, K> IbridgeServer<M, C, K>
where
    M: MailApi + Send + Sync + 'static,
    C: CalendarProvider + RemindersProvider + Send + Sync + 'static,
    K: ContactsProvider + Send + Sync + 'static,
{
    /// Shows the calendar and reminders tools, backed by `calendar`.
    #[must_use]
    pub fn with_calendar<C2>(self, calendar: Arc<C2>) -> IbridgeServer<M, C2, K>
    where
        C2: CalendarProvider + RemindersProvider + Send + Sync + 'static,
    {
        IbridgeServer::<M, C2, K>::build_with(
            self.access,
            self.account,
            self.mail,
            calendar,
            self.contacts,
            Tools3 {
                mail: self.mail_tools,
                calendar: Tools::Shown,
                contacts: self.contacts_tools,
                downloads: self.downloads,
            },
        )
    }

    /// Shows the contacts tools, backed by `contacts`.
    #[must_use]
    pub fn with_contacts<K2>(self, contacts: Arc<K2>) -> IbridgeServer<M, C, K2>
    where
        K2: ContactsProvider + Send + Sync + 'static,
    {
        IbridgeServer::<M, C, K2>::build_with(
            self.access,
            self.account,
            self.mail,
            self.calendar,
            contacts,
            Tools3 {
                mail: self.mail_tools,
                calendar: self.calendar_tools,
                contacts: Tools::Shown,
                downloads: self.downloads,
            },
        )
    }

    /// Shows `mail_save_attachment`, which saves files into `dir`.
    ///
    /// Only the local run modes call this. A hosted server never writes to disk.
    #[must_use]
    pub fn with_downloads(mut self, dir: PathBuf) -> Self {
        self.downloads = Some(Arc::from(dir));
        if self.access == Access::ReadWrite && self.mail_tools == Tools::Shown {
            self.router.enable_route(SAVE_ATTACHMENT);
        }
        self
    }

    /// Hides every contacts tool.
    #[must_use]
    pub fn without_contacts(mut self) -> Self {
        for name in CONTACTS_TOOLS {
            self.router.disable_route(*name);
        }
        self.contacts_tools = Tools::Hidden;
        self
    }

    /// Hides every calendar and reminders tool.
    #[must_use]
    pub fn without_calendar(mut self) -> Self {
        for name in CALENDAR_TOOLS {
            self.router.disable_route(*name);
        }
        self.calendar_tools = Tools::Hidden;
        self
    }

    /// Hides every mail tool. `account_status` stays.
    #[must_use]
    pub fn without_mail(mut self) -> Self {
        for name in MAIL_TOOLS {
            self.router.disable_route(*name);
        }
        self.mail_tools = Tools::Hidden;
        self
    }

    /// Whether write tools are hidden.
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        matches!(self.access, Access::ReadOnly)
    }

    /// Tools visible to the client, sorted by name.
    #[must_use]
    pub fn tools(&self) -> Vec<Tool> {
        self.router.list_all()
    }

    fn build(
        access: Access,
        account: AccountSnapshot,
        mail: Arc<M>,
        calendar: Arc<C>,
        contacts: Arc<K>,
    ) -> Self {
        let tools = Tools3 {
            mail: Tools::Shown,
            calendar: Tools::Hidden,
            contacts: Tools::Hidden,
            downloads: None,
        };
        Self::build_with(access, account, mail, calendar, contacts, tools)
    }

    fn build_with(
        access: Access,
        account: AccountSnapshot,
        mail: Arc<M>,
        calendar: Arc<C>,
        contacts: Arc<K>,
        tools: Tools3,
    ) -> Self {
        let Tools3 {
            mail: mail_tools,
            calendar: calendar_tools,
            contacts: contacts_tools,
            downloads,
        } = tools;
        let mut router = Self::tool_router() + Self::calendar_router() + Self::contacts_router();
        let mut hidden: Vec<&str> = Vec::new();
        if access == Access::ReadOnly {
            hidden.extend(WRITE_TOOLS);
            hidden.extend(CALENDAR_WRITE_TOOLS);
            hidden.extend(CONTACTS_WRITE_TOOLS);
        }
        if mail_tools == Tools::Hidden {
            hidden.extend(MAIL_TOOLS);
        }
        if downloads.is_none() {
            hidden.push(SAVE_ATTACHMENT);
        }
        if calendar_tools == Tools::Hidden {
            hidden.extend(CALENDAR_TOOLS);
        }
        if contacts_tools == Tools::Hidden {
            hidden.extend(CONTACTS_TOOLS);
        }
        for name in hidden {
            router.disable_route(name);
        }
        IbridgeServer {
            access,
            account,
            mail,
            calendar,
            contacts,
            mail_tools,
            calendar_tools,
            contacts_tools,
            downloads,
            gate: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
            router,
        }
    }
}

#[tool_router]
impl<M, C, K> IbridgeServer<M, C, K>
where
    M: MailApi + Send + Sync + 'static,
    C: CalendarProvider + RemindersProvider + Send + Sync + 'static,
    K: ContactsProvider + Send + Sync + 'static,
{
    /// Lists mailboxes with their roles and counts.
    ///
    /// # Errors
    ///
    /// Returns an MCP error when the mailbox list cannot be read.
    #[tool(
        title = "List mailboxes",
        description = "Lists mailboxes with their roles and counts.",
        annotations(read_only_hint = true, destructive_hint = false, open_world_hint = true),
        output_schema = rmcp::handler::server::tool::schema_for_output::<MailboxListOut>(),
    )]
    pub async fn mail_list_mailboxes(&self) -> Result<CallToolResult, ErrorData> {
        let _permit = self.permit().await?;
        let mailboxes = try_mail!(self.mail.list_mailboxes().await);
        let listed: Vec<MailboxOut> = mailboxes.iter().map(mailbox_out).collect();
        let summary = format!("{} mailboxes", listed.len());
        respond(&MailboxListOut { mailboxes: listed }, summary)
    }

    /// Searches messages, newest first.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorData::invalid_params`] when the page size is above 100
    /// or a filter is not usable, and an MCP error when the search cannot be run.
    #[tool(
        title = "Search mail",
        description = "Searches messages, newest first. Subjects are as the sender wrote them.",
        annotations(read_only_hint = true, destructive_hint = false, open_world_hint = true),
        output_schema = rmcp::handler::server::tool::schema_for_output::<SearchOut>(),
    )]
    pub async fn mail_search(
        &self,
        Parameters(params): Parameters<SearchParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let query = search_query(&params)?;
        let _permit = self.permit().await?;
        let page = try_mail!(self.mail.search(&query).await);
        let summary = if page.warnings == 0 {
            format!("{} messages", page.messages.len())
        } else {
            format!(
                "{} messages, {} skipped",
                page.messages.len(),
                page.warnings
            )
        };
        let messages = page.messages.iter().map(hit_out).collect();
        respond(
            &SearchOut {
                messages,
                next_cursor: page.next_cursor,
                warnings: page.warnings,
            },
            summary,
        )
    }

    /// Fetches one message, including its text and attachment list.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorData::invalid_params`] when the id or offset is not usable,
    /// and an MCP error when the message cannot be read.
    #[tool(
        title = "Get message",
        description = "Fetches one message, including its text and attachment list. The subject and body are as the sender wrote them.",
        annotations(read_only_hint = true, destructive_hint = false, open_world_hint = true),
        output_schema = rmcp::handler::server::tool::schema_for_output::<MessageOut>(),
    )]
    pub async fn mail_get_message(
        &self,
        Parameters(params): Parameters<GetMessageParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let id = require_id(&params.id)?;
        let offset = body_offset(params.offset)?;
        let _permit = self.permit().await?;
        let fetched = try_mail!(self.mail.get_message(&id, offset).await);
        let summary = format!("message from {}", fetched.message.from);
        respond(&message_out(&fetched.message, fetched.next_offset), summary)
    }

    /// Fetches one attachment as text or as a small inline file.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorData::invalid_params`] when the id or offset is not usable,
    /// and an MCP error when the part cannot be read.
    #[tool(
        title = "Get attachment",
        description = "Fetches one attachment as text or as a small inline file. The file name and text are as the sender wrote them.",
        annotations(read_only_hint = true, destructive_hint = false, open_world_hint = true),
        output_schema = rmcp::handler::server::tool::schema_for_output::<AttachmentOut>(),
    )]
    pub async fn mail_get_attachment(
        &self,
        Parameters(params): Parameters<GetAttachmentParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let id = require_id(&params.id)?;
        let offset = body_offset(params.offset)?;
        let _permit = self.permit().await?;
        let fetched = try_mail!(self.mail.get_attachment(&id, &params.part, offset).await);
        let part = fetched.attachment;
        let bytes_base64 = part
            .bytes
            .as_ref()
            .map(|bytes| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes));
        respond(
            &AttachmentOut {
                content_type: part.info.content_type,
                name: strip_hidden(&part.info.name),
                size: part.info.size,
                text: part.text.as_deref().map(strip_hidden),
                bytes_base64,
                next_offset: widen(fetched.next_offset),
            },
            "attachment".to_owned(),
        )
    }

    /// Saves one attachment into the download folder and returns its path.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorData::invalid_params`] when the id is not usable, and an MCP
    /// error when the part cannot be read or the file cannot be written.
    #[tool(
        title = "Save attachment to disk",
        description = "Saves one attachment into the download folder and returns the file path. Local installs only.",
        annotations(read_only_hint = false, destructive_hint = true, open_world_hint = true),
        output_schema = rmcp::handler::server::tool::schema_for_output::<SavedAttachmentOut>(),
    )]
    pub async fn mail_save_attachment(
        &self,
        Parameters(params): Parameters<SaveAttachmentParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.reject_write()?;
        let Some(dir) = self.downloads.clone() else {
            return Err(ErrorData::invalid_params("tool not found", None));
        };
        let id = require_id(&params.id)?;
        let _permit = self.permit().await?;
        let file = try_mail!(self.mail.get_attachment_bytes(&id, &params.part).await);
        let Some(bytes) = file.bytes else {
            return mapped(&CoreError::Unsupported("saving attachments"));
        };
        let name = safe_name(&file.info.name, &file.info.part);
        let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let written = tokio::task::spawn_blocking(move || save_unique(&dir, &name, &bytes))
            .await
            .map_err(|_| ErrorData::internal_error("internal error", None))?;
        let path = match written {
            Ok(path) => path,
            Err(error) => {
                return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                    "the attachment could not be saved: {}",
                    error.kind()
                ))]));
            }
        };
        respond(
            &SavedAttachmentOut {
                path: path.display().to_string(),
                size,
                content_type: file.info.content_type,
            },
            "attachment saved".to_owned(),
        )
    }

    /// Saves a draft in Drafts.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorData::invalid_params`] when the draft is not usable,
    /// and an MCP error when the draft cannot be saved.
    #[tool(
        title = "Create draft",
        description = "Saves a draft in Drafts.",
        annotations(read_only_hint = false, destructive_hint = true, open_world_hint = true),
        output_schema = rmcp::handler::server::tool::schema_for_output::<IdOut>(),
    )]
    pub async fn mail_create_draft(
        &self,
        Parameters(params): Parameters<SendParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.reject_write()?;
        let draft = draft_from(&params)?;
        let _permit = self.permit().await?;
        let id = try_mail!(self.mail.create_draft(&draft).await);
        let token = encode(&id);
        respond(&IdOut { id: token }, "draft saved".to_owned())
    }

    /// Sends a message and saves a copy in Sent Messages.
    ///
    /// A failed Sent copy is a warning on a successful send, not a failed send.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorData::invalid_params`] when the message is not usable,
    /// and an MCP error when SMTP refuses the message.
    #[tool(
        title = "Send message",
        description = "Sends a message and saves a copy in Sent Messages.",
        annotations(read_only_hint = false, destructive_hint = true, open_world_hint = true),
        output_schema = rmcp::handler::server::tool::schema_for_output::<SendOut>(),
    )]
    pub async fn mail_send(
        &self,
        Parameters(params): Parameters<SendParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.reject_write()?;
        let draft = draft_from(&params)?;
        let _permit = self.permit().await?;
        let sent = try_mail!(self.mail.send(&draft).await);
        let (id, warning, summary) = match sent.id {
            Some(id) => (Some(encode(&id)), None, "sent".to_owned()),
            None => (
                None,
                Some(SENT_COPY_WARNING.to_owned()),
                SENT_COPY_WARNING.to_owned(),
            ),
        };
        respond(&SendOut { id, warning }, summary)
    }

    /// Unsubscribes from the sender of a message, like an unsubscribe button in a mail app.
    ///
    /// The tool takes the message id and nothing else: the address comes from the
    /// message's own `List-Unsubscribe` header, which the sender wrote.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorData::invalid_params`] when the id is not usable, and an MCP error
    /// when the message cannot be read or SMTP refuses the email.
    #[tool(
        title = "Unsubscribe",
        description = "Unsubscribes from the sender of a message, like an unsubscribe button. Takes only the message id: the sender's own unsubscribe address, if the message offers one, is used. An unsubscribe email is sent from the account and a copy is saved in Sent Messages. If the sender offers only a web link, nothing is sent and the link is returned as the sender wrote it.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        ),
        output_schema = rmcp::handler::server::tool::schema_for_output::<UnsubscribedOut>(),
    )]
    pub async fn mail_unsubscribe(
        &self,
        Parameters(params): Parameters<UnsubscribeParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.reject_write()?;
        let id = require_id(&params.id)?;
        let _permit = self.permit().await?;
        match try_mail!(self.mail.unsubscribe(&id).await) {
            Unsubscribed::Emailed(sent) => {
                let (id, warning, summary) = match sent.id {
                    Some(id) => (Some(encode(&id)), None, "unsubscribe email sent".to_owned()),
                    None => (
                        None,
                        Some(SENT_COPY_WARNING.to_owned()),
                        SENT_COPY_WARNING.to_owned(),
                    ),
                };
                respond(
                    &UnsubscribedOut {
                        status: UnsubscribeStatus::Emailed,
                        id,
                        warning,
                        links: Vec::new(),
                        note: "An unsubscribe email was sent to the sender. The sender decides when it takes effect.".to_owned(),
                    },
                    summary,
                )
            }
            Unsubscribed::Links(links) => respond(
                &UnsubscribedOut {
                    status: UnsubscribeStatus::LinkOnly,
                    id: None,
                    warning: None,
                    links: links.iter().map(|link| strip_hidden(link)).collect(),
                    note: LINK_ONLY_NOTE.to_owned(),
                },
                "only a web link is on offer".to_owned(),
            ),
            _ => Ok(CallToolResult::error(vec![ContentBlock::text(
                "this message does not offer unsubscribe: it has no usable List-Unsubscribe header",
            )])),
        }
    }

    /// Moves a message to a mailbox or a role.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorData::invalid_params`] when the destination is not usable,
    /// and an MCP error when the move cannot be done.
    #[tool(
        title = "Move message",
        description = "Moves a message to a mailbox or a role.",
        annotations(read_only_hint = false, destructive_hint = true, open_world_hint = true),
        output_schema = rmcp::handler::server::tool::schema_for_output::<MoveOut>(),
    )]
    pub async fn mail_move(
        &self,
        Parameters(params): Parameters<MoveParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.reject_write()?;
        let id = require_id(&params.id)?;
        let destination = destination(&params)?;
        let _permit = self.permit().await?;
        try_mail!(self.mail.move_message(&id, &destination).await);
        respond(&MoveOut { moved: true }, "moved".to_owned())
    }

    /// Sets or clears seen and flagged. The same call again changes nothing.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorData::invalid_params`] when the id is not usable,
    /// and an MCP error when the flags cannot be stored.
    #[tool(
        title = "Set message flags",
        description = "Sets or clears seen and flagged. Repeating the same change does nothing more.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = true
        ),
        output_schema = rmcp::handler::server::tool::schema_for_output::<FlagsOut>(),
    )]
    pub async fn mail_set_flags(
        &self,
        Parameters(params): Parameters<FlagParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.reject_write()?;
        let id = require_id(&params.id)?;
        let flags = FlagChange {
            seen: params.seen,
            flagged: params.flagged,
        };
        let _permit = self.permit().await?;
        try_mail!(self.mail.set_flags(&id, &flags).await);
        respond(&FlagsOut { updated: true }, "flags updated".to_owned())
    }

    /// Reports the signed-in address, each service, and the server version.
    ///
    /// # Errors
    ///
    /// Returns an MCP error when the status cannot be built.
    #[tool(
        title = "Get account status",
        description = "Reports the signed-in address, each service, and the server version.",
        annotations(read_only_hint = true, destructive_hint = false, open_world_hint = false),
        output_schema = rmcp::handler::server::tool::schema_for_output::<AccountStatusOut>(),
    )]
    pub async fn account_status(&self) -> Result<CallToolResult, ErrorData> {
        let _permit = self.permit().await?;
        let status = AccountStatusOut {
            apple_id: self.account.apple_id.as_str().to_owned(),
            services: vec![
                service_out("mail", &self.account.mail),
                service_out("calendar", &self.account.calendar),
                service_out("contacts", &self.account.contacts),
            ],
            version: env!("CARGO_PKG_VERSION"),
        };
        let summary = status_summary(&status);
        respond(&status, summary)
    }

    pub(crate) fn reject_write(&self) -> Result<(), ErrorData> {
        if self.access == Access::ReadOnly {
            return Err(ErrorData::invalid_params("tool not found", None));
        }
        Ok(())
    }

    pub(crate) async fn permit(&self) -> Result<OwnedSemaphorePermit, ErrorData> {
        Arc::clone(&self.gate)
            .acquire_owned()
            .await
            .map_err(|_| ErrorData::internal_error("internal error", None))
    }
}

pub(crate) fn respond<T: serde::Serialize>(
    value: &T,
    summary: String,
) -> Result<CallToolResult, ErrorData> {
    let json = serde_json::to_value(value)
        .map_err(|_| ErrorData::internal_error("internal error", None))?;
    let mut result = CallToolResult::structured(json);
    // Claude reads the text content, not `structuredContent`. `structured` already put the
    // serialized JSON in `content`, which the MCP spec asks for; the summary goes in front.
    result.content.insert(0, ContentBlock::text(summary));
    Ok(result)
}

pub(crate) fn mapped(error: &CoreError) -> Result<CallToolResult, ErrorData> {
    match map_core_error(error) {
        MappedError::Rpc(data) => Err(data),
        MappedError::Tool(message) => Ok(CallToolResult::error(vec![ContentBlock::text(
            message.into_owned(),
        )])),
    }
}

pub(crate) fn page_limit(limit: u32) -> Result<u32, ErrorData> {
    if limit == 0 {
        return Ok(DEFAULT_LIMIT);
    }
    if limit > MAX_LIMIT {
        return Err(ErrorData::invalid_params("limit must be at most 100", None));
    }
    Ok(limit)
}

fn body_offset(offset: u64) -> Result<usize, ErrorData> {
    usize::try_from(offset).map_err(|_| ErrorData::invalid_params("offset is too large", None))
}

fn require_id(token: &str) -> Result<MessageId, ErrorData> {
    decode(token).map_err(|_| ErrorData::invalid_params("invalid message id", None))
}

fn require_path(path: &str) -> Result<MailboxPath, ErrorData> {
    MailboxPath::try_from(path).map_err(|_| ErrorData::invalid_params("invalid mailbox path", None))
}

fn parse_role(name: &str) -> Result<MailboxRole, ErrorData> {
    match name {
        "inbox" => Ok(MailboxRole::Inbox),
        "sent" => Ok(MailboxRole::Sent),
        "drafts" => Ok(MailboxRole::Drafts),
        "trash" => Ok(MailboxRole::Trash),
        "junk" => Ok(MailboxRole::Junk),
        "archive" => Ok(MailboxRole::Archive),
        "notes" => Ok(MailboxRole::Notes),
        _ => Err(ErrorData::invalid_params("unknown mailbox role", None)),
    }
}

fn role_name(role: MailboxRole) -> &'static str {
    match role {
        MailboxRole::Inbox => "inbox",
        MailboxRole::Sent => "sent",
        MailboxRole::Drafts => "drafts",
        MailboxRole::Trash => "trash",
        MailboxRole::Junk => "junk",
        MailboxRole::Archive => "archive",
        MailboxRole::Notes => "notes",
        MailboxRole::Other | _ => "other",
    }
}

fn search_query(params: &SearchParams) -> Result<MailSearch, ErrorData> {
    let mailbox = params.mailbox.as_deref().map(require_path).transpose()?;
    let role = params.role.as_deref().map(parse_role).transpose()?;
    Ok(MailSearch {
        mailbox,
        role,
        from: params.from.clone(),
        to: params.to.clone(),
        subject: params.subject.clone(),
        text: params.text.clone(),
        since: params.since.clone(),
        before: params.before.clone(),
        unread_only: params.unread.unwrap_or(false),
        flagged_only: params.flagged.unwrap_or(false),
        limit: page_limit(params.limit)?,
        cursor: params.cursor.clone(),
    })
}

fn draft_from(params: &SendParams) -> Result<Draft, ErrorData> {
    let reply_to = params.reply_to_id.as_deref().map(require_id).transpose()?;
    Ok(Draft {
        to: params.to.clone(),
        subject: params.subject.clone(),
        body: params.body.clone(),
        from: params.from.clone(),
        reply_to,
    })
}

fn destination(params: &MoveParams) -> Result<MailDest, ErrorData> {
    match (&params.mailbox, &params.role) {
        (Some(path), None) => Ok(MailDest::Path(require_path(path)?)),
        (None, Some(role)) => Ok(MailDest::Role(parse_role(role)?)),
        _ => Err(ErrorData::invalid_params(
            "move needs a mailbox or a role",
            None,
        )),
    }
}

fn mailbox_out(mailbox: &Mailbox) -> MailboxOut {
    MailboxOut {
        path: mailbox.path.as_str().to_owned(),
        role: role_name(mailbox.role).to_owned(),
        total: mailbox.total,
        unread: mailbox.unread,
    }
}

fn hit_out(hit: &MessageSummary) -> SearchHitOut {
    SearchHitOut {
        id: encode(&hit.id),
        from: strip_hidden(&hit.from),
        subject: strip_hidden(&hit.subject),
        date: hit.date.clone(),
        unread: hit.unread,
        flagged: hit.flagged,
    }
}

fn message_out(message: &Message, next_offset: Option<usize>) -> MessageOut {
    MessageOut {
        id: encode(&message.id),
        from: strip_hidden(&message.from),
        to: message.to.iter().map(|to| strip_hidden(to)).collect(),
        subject: strip_hidden(&message.subject),
        date: message.date.clone(),
        body: strip_hidden(&message.body),
        attachments: message
            .attachments
            .iter()
            .map(|info| AttachmentInfoOut {
                part: info.part.clone(),
                content_type: info.content_type.clone(),
                size: info.size,
                name: strip_hidden(&info.name),
            })
            .collect(),
        unsubscribe: unsubscribe_out(message.unsubscribe.as_ref()),
        next_offset: widen(next_offset),
    }
}

fn unsubscribe_out(options: Option<&Unsubscribe>) -> UnsubscribeOut {
    let methods: Vec<UnsubscribeMethodOut> = options
        .map_or_default(Unsubscribe::methods)
        .into_iter()
        .filter_map(|method| match method {
            UnsubscribeMethod::OneClick => Some(UnsubscribeMethodOut::OneClick),
            UnsubscribeMethod::Mailto => Some(UnsubscribeMethodOut::Mailto),
            UnsubscribeMethod::Link => Some(UnsubscribeMethodOut::Link),
            _ => None,
        })
        .collect();
    UnsubscribeOut {
        available: !methods.is_empty(),
        methods,
    }
}

fn widen(offset: Option<usize>) -> Option<u64> {
    offset.map(|offset| u64::try_from(offset).unwrap_or(u64::MAX))
}

fn service_out(name: &str, status: &ServiceStatus) -> ServiceOut {
    match status {
        ServiceStatus::On => ServiceOut {
            name: name.to_owned(),
            status: ServiceState::On,
            reason: None,
        },
        ServiceStatus::Off { reason } => ServiceOut {
            name: name.to_owned(),
            status: ServiceState::Off,
            reason: Some(reason.clone()),
        },
    }
}

fn status_summary(status: &AccountStatusOut) -> String {
    let mut parts = Vec::with_capacity(status.services.len() + 2);
    parts.push(format!("signed in as {}", status.apple_id));
    for service in &status.services {
        if let Some(reason) = &service.reason {
            parts.push(format!("{} off: {reason}", service.name));
        } else {
            parts.push(format!("{} on", service.name));
        }
    }
    parts.push(format!("version {}", status.version));
    parts.join("; ")
}

#[expect(
    clippy::unused_async_trait_impl,
    reason = "the generated tool listing returns without waiting"
)]
#[tool_handler(router = self.router, name = "ibridge")]
impl<M, C, K> ServerHandler for IbridgeServer<M, C, K>
where
    M: MailApi + Send + Sync + 'static,
    C: CalendarProvider + RemindersProvider + Send + Sync + 'static,
    K: ContactsProvider + Send + Sync + 'static,
{
}

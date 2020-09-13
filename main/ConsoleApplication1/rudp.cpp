#include "unistd.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
//#include <netdb.h>
#include <fcntl.h>
#include <sys/types.h>
//#include <sys/time.h>
//#include <sys/file.h>

#ifdef _WIN32
  #include "gettimeofday.h"
 // int gettimeofday(struct timeval *tv, struct timezone *tz);
 // #include <winsock2.h>
//  #include <ws2def.h>
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
#endif
#include <time.h>

#include "event.h"
#include "rudp.h"
#include "rudp_api.h"

/** rudp.c
 *
 * This file implements the majority of the logic for RUDP sending and receiving
 *
 * Author: Andrew Keating
 */

#define DROP 0 /* Probability of packet loss */

typedef enum {SYN_SENT = 0, OPENING, OPEN, FIN_SENT} rudp_state_t; /* RUDP States */

typedef enum {_false = 0, _true } bool_t;

typedef struct rudp_packet_t {
  rudp_hdr header;
  int payload_length;
  char payload[RUDP_MAXPKTSIZE];
}rudp_packet;

/* Outgoing data queue */
typedef struct net_data_t {
  void *item;
  int len;
  struct net_data_t *next;
}net_data;

typedef struct sender_session_t {
  rudp_state_t status; /* Protocol state */
  uint32_t seqno;
  rudp_packet *sliding_window[RUDP_WINDOW];
  int retransmission_attempts[RUDP_WINDOW];
  net_data *data_queue; /* Queue of unsent data */
  bool_t session_finished; /* Has the FIN we sent been ACKed? */
  void *syn_timeout_arg; /* Argument pointer used to delete SYN timeout event */
  void *fin_timeout_arg; /* Argument pointer used to delete FIN timeout event */
  void *data_timeout_arg[RUDP_WINDOW]; /* Argument pointers used to delete DATA timeout events */
  int syn_retransmit_attempts;
  int fin_retransmit_attempts;
}sender_session;

typedef struct receiver_session_t {
  rudp_state_t status; /* Protocol state */
  uint32_t expected_seqno;
  bool_t session_finished; /* Have we received a FIN from the sender? */
}receiver_session;

typedef struct session_t {
  sender_session *sender;
  receiver_session *receiver;
  struct sockaddr_in address;
  struct session_t *next;
}session;

/* Keeps state for potentially multiple active sockets */
typedef struct rudp_socket_list_t {
  rudp_socket_t rsock;
  bool_t close_requested;
  int (*recv_handler)(rudp_socket_t, struct sockaddr_in *, char *, int);
  int (*handler)(rudp_socket_t, rudp_event_t, struct sockaddr_in *);
  session *sessions_list_head;
  struct rudp_socket_list_t *next;
}rudp_socket_list;

/* Arguments for timeout callback function */
typedef struct timeoutargs_t {
  rudp_socket_t fd;
  rudp_packet *packet;
  struct sockaddr_in *recipient;
}timeoutargs;

/* Prototypes */
void create_sender_session(rudp_socket_list *socket, uint32_t seqno, struct sockaddr_in *to, net_data **data_queue);
void create_receiver_session(rudp_socket_list *socket, uint32_t seqno, struct sockaddr_in *addr);
rudp_packet *create_rudp_packet(uint16_t type, uint32_t seqno, int len, char *payload);
int compare_sockaddr(struct sockaddr_in *s1, struct sockaddr_in *s2);
int receive_callback(int file, void *arg);
int timeout_callback(int retry_attempts, void *args);
int send_packet(bool_t is_ack, rudp_socket_t rsocket, rudp_packet *p, struct sockaddr_in *recipient);

/* Global variables */
bool_t rng_seeded = _false;
rudp_socket_list *socket_list_head = NULL;

/* Creates a new sender session and appends it to the socket's session list */
void create_sender_session(rudp_socket_list *socket, uint32_t seqno, struct sockaddr_in *to, net_data **data_queue) {
  session *new_session;
  sender_session *new_sender_session;
  int i;

  new_session = (session *)malloc(sizeof(session));
  if(new_session == NULL) {
    fprintf(stderr, "create_sender_session: Error allocating memory\n");
    return;
  }
  new_session->address = *to;
  new_session->next = NULL;
  new_session->receiver = NULL;

  new_sender_session = (sender_session *)malloc(sizeof(sender_session));
  if(new_sender_session == NULL) {
    fprintf(stderr, "create_sender_session: Error allocating memory\n");
    return;
  }
  new_sender_session->status = SYN_SENT;
  new_sender_session->seqno = seqno;
  new_sender_session->session_finished = _false;
  /* Add data to the new session's queue */
  new_sender_session->data_queue = *data_queue;
  new_session->sender = new_sender_session;

  for(i = 0; i < RUDP_WINDOW; i++) {
    new_sender_session->retransmission_attempts[i] = 0;
    new_sender_session->data_timeout_arg[i] = 0;
    new_sender_session->sliding_window[i] = NULL;
  }    
  new_sender_session->syn_retransmit_attempts = 0;
  new_sender_session->fin_retransmit_attempts = 0;
  
  if(socket->sessions_list_head == NULL) {
    socket->sessions_list_head = new_session;
  }
  else {
    session *curr_session = socket->sessions_list_head;
    while(curr_session->next != NULL) {
      curr_session = curr_session->next;
    }
    curr_session->next = new_session;
  }
}

/* Creates a new receiver session and appends it to the socket's session list */
void create_receiver_session(rudp_socket_list *socket, uint32_t seqno, struct sockaddr_in *addr) {
  session *new_session;
  receiver_session *new_receiver_session;
  new_session = (session *)malloc(sizeof(session));
  if(new_session == NULL) {
    fprintf(stderr, "create_receiver_session: Error allocating memory\n");
    return;
  }
  new_session->address = *addr;
  new_session->next = NULL;
  new_session->sender = NULL;
  
  new_receiver_session = (receiver_session *)malloc(sizeof(receiver_session));
  if(new_receiver_session == NULL) {
    fprintf(stderr, "create_receiver_session: Error allocating memory\n");
    return;
  }
  new_receiver_session->status = OPENING;
  new_receiver_session->session_finished = _false;
  new_receiver_session->expected_seqno = seqno;
  new_session->receiver = new_receiver_session;
  
  if(socket->sessions_list_head == NULL) {
    socket->sessions_list_head = new_session;
  }
  else {
    session *curr_session = socket->sessions_list_head;
    while(curr_session->next != NULL) {
      curr_session = curr_session->next;
    }
    curr_session->next = new_session;
  }
}

/* Allocates a RUDP packet and returns a pointer to it */
rudp_packet *create_rudp_packet(uint16_t type, uint32_t seqno, int len, char *payload) {
  rudp_hdr header;
  rudp_packet *packet;
  header.version = RUDP_VERSION;
  header.type = type;
  header.seqno = seqno;
  
  packet = (rudp_packet *)malloc(sizeof(rudp_packet));
  if(packet == NULL) {
    fprintf(stderr, "create_rudp_packet: Error allocating memory for packet\n");
    return NULL;
  }
  packet->header = header;
  packet->payload_length = len;
  memset(&packet->payload, 0, RUDP_MAXPKTSIZE);
  if(payload != NULL)
    memcpy(&packet->payload, payload, len);
  
  return packet;
}

/* Returns 1 if the two sockaddr_in structs are equal and 0 if not */
int compare_sockaddr(struct sockaddr_in *s1, struct sockaddr_in *s2) {
  char sender[16];
  char recipient[16];
  strcpy_s(sender, inet_ntoa(s1->sin_addr));
  strcpy_s(recipient, inet_ntoa(s2->sin_addr));
  
  return ((s1->sin_family == s2->sin_family) && (strcmp(sender, recipient) == 0) && (s1->sin_port == s2->sin_port));
}

/* Creates and returns a RUDP socket */
rudp_socket_t rudp_socket(int port) {
  int sockfd;
  struct sockaddr_in address;
  rudp_socket_t socket_val;
  rudp_socket_list *new_socket;

  if(rng_seeded == _false) {
    srand((int)time(NULL));
    rng_seeded = _true;
  }

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if(sockfd < 0) {
    perror("socket");
    return (rudp_socket_t)NULL;
  }

  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_ANY);
  address.sin_port = htons(port);

  if( bind(sockfd, (const struct sockaddr *) &address, sizeof(address)) < 0) {
    perror("bind");
    return NULL;
  }

  socket_val = (rudp_socket_t)sockfd;

  /* Create new socket and add to list of sockets */
  new_socket = (rudp_socket_list *)malloc(sizeof(rudp_socket_list));
  if(new_socket == NULL) {
    fprintf(stderr, "rudp_socket: Error allocating memory for socket list\n");
    return (rudp_socket_t) -1;
  }
  new_socket->rsock = socket_val;
  new_socket->close_requested = _false;
  new_socket->sessions_list_head = NULL;
  new_socket->next = NULL;
  new_socket->handler = NULL;
  new_socket->recv_handler = NULL;

  if(socket_list_head == NULL) {
    socket_list_head = new_socket;
  }
  else {
    rudp_socket_list *curr = socket_list_head;
    while(curr->next != NULL) {
      curr = curr->next;
    }
    curr->next = new_socket;
  }

  /* Register callback event for this socket descriptor */
  if(event_fd(sockfd, receive_callback, (void*) sockfd, "receive_callback") < 0) {
    fprintf(stderr, "Error registering receive callback function");
  }

  return socket;
}

/* Callback function executed when something is received on fd */
int receive_callback(int file, void *arg) {
  char buf[sizeof(rudp_packet)];
  struct sockaddr_in sender;
  int32_t sender_length;
  rudp_packet *received_packet;
  rudp_hdr rudpheader;
  char type[5];
  short t;
  sender_length = sizeof(struct sockaddr_in);
  recvfrom(file, (char *)&buf, sizeof(rudp_packet), 0, (sockaddr *)&sender, &sender_length);

  received_packet = (rudp_packet *)malloc(sizeof(rudp_packet));
  if(received_packet == NULL) {
    fprintf(stderr, "receive_callback: Error allocating packet\n");
    return -1;
  }
  memcpy(received_packet, &buf, sizeof(rudp_packet));
  
  rudpheader = received_packet->header;

  t = rudpheader.type;
  if(t == 1)
    strcpy_s(type, "DATA");
  else if(t == 2)
    strcpy_s(type, "ACK");
  else if(t == 4)
    strcpy_s(type, "SYN");
  else if(t==5)
    strcpy_s(type, "FIN");
  else
    strcpy_s(type, "BAD");

  printf("Received %s packet from %s:%d seq number=%u on socket=%d\n",type, 
       inet_ntoa(sender.sin_addr), ntohs(sender.sin_port),rudpheader.seqno,file);

  /* Locate the correct socket in the socket list */
  if(socket_list_head == NULL) {
    fprintf(stderr, "Error: attempt to receive on invalid socket. No sockets in the list\n");
    return -1;
  }
  else {
    /* We have sockets to check */
    rudp_socket_list *curr_socket = socket_list_head;
    while(curr_socket != NULL) {
      if((int)curr_socket->rsock == file) {
        break;
      }
      curr_socket = curr_socket->next;
    }
    if((int)curr_socket->rsock == file) {
      /* We found the correct socket, now see if a session already exists for this peer */
      if(curr_socket->sessions_list_head == NULL) {
        /* The list is empty, so we check if the sender has initiated the protocol properly (by sending a SYN) */
        if(rudpheader.type == RUDP_SYN) {
          /* SYN Received. Create a new session at the head of the list */
          uint32_t seqno = rudpheader.seqno + 1;
          create_receiver_session(curr_socket, seqno, &sender);
          /* Respond with an ACK */
          rudp_packet *p = create_rudp_packet(RUDP_ACK, seqno, 0, NULL);
          send_packet(_true, (rudp_socket_t)file, p, &sender);
          free(p);
        }
        else {
          /* No sessions exist and we got a non-SYN, so ignore it */
        }
      }
      else {
        /* Some sessions exist to be checked */
        bool_t session_found = _false;
        session *curr_session = curr_socket->sessions_list_head;
        session *last_session;
        while(curr_session != NULL) {
          if(curr_session->next == NULL) {
            last_session = curr_session;
          }
          if(compare_sockaddr(&curr_session->address, &sender) == 1) {
            /* Found an existing session */
            session_found = _true;
            break;
          }

          curr_session = curr_session->next;
        }
        if(session_found == false) {
          /* No session was found for this peer */
          if(rudpheader.type == RUDP_SYN) {
            /* SYN Received. Send an ACK and create a new session */
            uint32_t seqno = rudpheader.seqno + 1;
            create_receiver_session(curr_socket, seqno, &sender);          
            rudp_packet *p = create_rudp_packet(RUDP_ACK, seqno, 0, NULL);
            send_packet(_true, (rudp_socket_t)file, p, &sender);
            free(p);
          }
          else {
            /* Session does not exist and non-SYN received - ignore it */
          }
        }
        else {
          /* We found a matching session */ 
          if(rudpheader.type == RUDP_SYN) {
            if(curr_session->receiver == NULL || curr_session->receiver->status == OPENING) {
              /* Create a new receiver session and ACK the SYN*/
              receiver_session *new_receiver_session = (receiver_session *)malloc(sizeof(receiver_session));
              if(new_receiver_session == NULL) {
                fprintf(stderr, "receive_callback: Error allocating receiver session\n");
                return -1;
              }
              new_receiver_session->expected_seqno = rudpheader.seqno + 1;
              new_receiver_session->status = OPENING;
              new_receiver_session->session_finished = _false;
              curr_session->receiver = new_receiver_session;

              uint32_t seqno = curr_session->receiver->expected_seqno;
              rudp_packet *p = create_rudp_packet(RUDP_ACK, seqno, 0, NULL);
              send_packet(_true, (rudp_socket_t)file, p, &sender);
              free(p);
            }
            else {
              /* Received a SYN when there is already an active receiver session, so we ignore it */
            }
          }
          if(rudpheader.type == RUDP_ACK) {
            uint32_t ack_sqn = received_packet->header.seqno;
            if(curr_session->sender->status == SYN_SENT) {
              /* This an ACK for a SYN */
              uint32_t syn_sqn = curr_session->sender->seqno;
              if( (ack_sqn - 1) == syn_sqn) {
                /* Delete the retransmission timeout */
                event_timeout_delete(timeout_callback, curr_session->sender->syn_timeout_arg);
                timeoutargs *t = (timeoutargs *)curr_session->sender->syn_timeout_arg;
                free(t->packet);
                free(t->recipient);
                free(t);
                curr_session->sender->status = OPEN;
                while(curr_session->sender->data_queue != NULL) {
                  /* Check if the window is already full */
                  if(curr_session->sender->sliding_window[RUDP_WINDOW-1] != NULL) {
                    break;
                  }
                  else {
                    int index;
                    int i;
                    /* Find the first unused window slot */
                    for(i = RUDP_WINDOW-1; i >= 0; i--) {
                      if(curr_session->sender->sliding_window[i] == NULL) {
                        index = i;
                      }
                    }
                    /* Send packet, add to window and remove from queue */
                    uint32_t seqno = ++syn_sqn;
                    int len = curr_session->sender->data_queue->len;
                    char *payload = (char *)curr_session->sender->data_queue->item;
                    rudp_packet *datap = create_rudp_packet(RUDP_DATA, seqno, len, payload);
                    curr_session->sender->seqno += 1;
                    curr_session->sender->sliding_window[index] = datap;
                    curr_session->sender->retransmission_attempts[index] = 0;
                    net_data *temp = curr_session->sender->data_queue;
                    curr_session->sender->data_queue = curr_session->sender->data_queue->next;
                    free(temp->item);
                    free(temp);

                    send_packet(_false, (rudp_socket_t)file, datap, &sender);
                  }
                }
              }
            }
            else if(curr_session->sender->status == OPEN) {
              /* This is an ACK for DATA */
              if(curr_session->sender->sliding_window[0] != NULL) {
                if(curr_session->sender->sliding_window[0]->header.seqno == (rudpheader.seqno-1)) {
                  /* Correct ACK received. Remove the first window item and shift the rest left */
                  event_timeout_delete(timeout_callback, curr_session->sender->data_timeout_arg[0]);
                  timeoutargs *args = (timeoutargs *)curr_session->sender->data_timeout_arg[0];
                  free(args->packet);
                  free(args->recipient);
                  free(args);
                  free(curr_session->sender->sliding_window[0]);

                  int i;
                  if(RUDP_WINDOW == 1) {
                    curr_session->sender->sliding_window[0] = NULL;
                    curr_session->sender->retransmission_attempts[0] = 0;
                    curr_session->sender->data_timeout_arg[0] = NULL;
                  }
                  else {
                    for(i = 0; i < RUDP_WINDOW - 1; i++) {
                      curr_session->sender->sliding_window[i] = curr_session->sender->sliding_window[i+1];
                      curr_session->sender->retransmission_attempts[i] = curr_session->sender->retransmission_attempts[i+1];
                      curr_session->sender->data_timeout_arg[i] = curr_session->sender->data_timeout_arg[i+1];

                      if(i == RUDP_WINDOW-2) {
                        curr_session->sender->sliding_window[i+1] = NULL;
                        curr_session->sender->retransmission_attempts[i+1] = 0;
                        curr_session->sender->data_timeout_arg[i+1] = NULL;
                      }
                    }
                  }

                  while(curr_session->sender->data_queue != NULL) {
                    if(curr_session->sender->sliding_window[RUDP_WINDOW-1] != NULL) {
                      break;
                    }
                    else {
                      int index;
                      int i;
                      /* Find the first unused window slot */
                      for(i = RUDP_WINDOW-1; i >= 0; i--) {
                        if(curr_session->sender->sliding_window[i] == NULL) {
                          index = i;
                        }
                      }                      
                      /* Send packet, add to window and remove from queue */
                      curr_session->sender->seqno = curr_session->sender->seqno + 1;                      
                      uint32_t seqno = curr_session->sender->seqno;
                      int len = curr_session->sender->data_queue->len;
                      char *payload = (char *)curr_session->sender->data_queue->item;
                      rudp_packet *datap = create_rudp_packet(RUDP_DATA, seqno, len, payload);
                      curr_session->sender->sliding_window[index] = datap;
                      curr_session->sender->retransmission_attempts[index] = 0;
                      net_data *temp = curr_session->sender->data_queue;
                      curr_session->sender->data_queue = curr_session->sender->data_queue->next;
                      free(temp->item);
                      free(temp);
                      send_packet(_false, (rudp_socket_t)file, datap, &sender);
                    }
                  }
                  if(curr_socket->close_requested) {
                    /* Can the socket be closed? */
                    session *head_sessions = curr_socket->sessions_list_head;
                    while(head_sessions != NULL) {
                      if(head_sessions->sender->session_finished == _false) {
                        if(head_sessions->sender->data_queue == NULL &&  
                           head_sessions->sender->sliding_window[0] == NULL && 
                           head_sessions->sender->status == OPEN) {
                          head_sessions->sender->seqno += 1;                      
                          rudp_packet *p = create_rudp_packet(RUDP_FIN, head_sessions->sender->seqno, 0, NULL);
                          send_packet(_false, (rudp_socket_t)file, p, &head_sessions->address);
                          free(p);
                          head_sessions->sender->status = FIN_SENT;
                        }
                      }
                      head_sessions = head_sessions->next;
                    }
                  }
                }
              }
            }
            else if(curr_session->sender->status == FIN_SENT) {
              /* Handle ACK for FIN */
              if( (curr_session->sender->seqno + 1) == received_packet->header.seqno) {
                event_timeout_delete(timeout_callback, curr_session->sender->fin_timeout_arg);
                timeoutargs *t = (timeoutargs *)curr_session->sender->fin_timeout_arg;
                free(t->packet);
                free(t->recipient);
                free(t);
                curr_session->sender->session_finished = _true;
                if(curr_socket->close_requested) {
                  /* See if we can close the socket */
                  session *head_sessions = curr_socket->sessions_list_head;
                  bool_t all_done = _true;
                  while(head_sessions != NULL) {
                    if(head_sessions->sender->session_finished == _false) {
                      all_done = _false;
                    }
                    else if(head_sessions->receiver != NULL && head_sessions->receiver->session_finished == _false) {
                      all_done = _false;
                    }
                    else {
                      free(head_sessions->sender);
                      if(head_sessions->receiver) {
                        free(head_sessions->receiver);
                      }
                    }

                    session *temp = head_sessions;
                    head_sessions = head_sessions->next;
                    free(temp);
                  }
                  if(all_done) {
                    if(curr_socket->handler != NULL) {
                      curr_socket->handler((rudp_socket_t)file, RUDP_EVENT_CLOSED, &sender);
                      event_fd_delete(receive_callback, (rudp_socket_t)file);
                      _close(file);
                      free(curr_socket);
                    }
                  }
                }
              }
              else {
                /* Received incorrect ACK for FIN - ignore it */
              }
            }
          }
          else if(rudpheader.type == RUDP_DATA) {
            /* Handle DATA packet. If the receiver is OPENING, it can transition to OPEN */
            if(curr_session->receiver->status == OPENING) {
              if(rudpheader.seqno == curr_session->receiver->expected_seqno) {
                curr_session->receiver->status = OPEN;
              }
            }

            if(rudpheader.seqno == curr_session->receiver->expected_seqno) {
              /* Sequence numbers match - ACK the data */
              uint32_t seqno = rudpheader.seqno + 1;
              curr_session->receiver->expected_seqno = seqno;
              rudp_packet *p = create_rudp_packet(RUDP_ACK, seqno, 0, NULL);
  
              send_packet(_true, (rudp_socket_t)file, p, &sender);
              free(p);
              
              /* Pass the data up to the application */
              if(curr_socket->recv_handler != NULL)
                curr_socket->recv_handler((rudp_socket_t)file, &sender, 
                              (char *)&received_packet->payload,
							  received_packet->payload_length);
            }
            /* Handle the case where an ACK was lost */
            else if(SEQ_GEQ(rudpheader.seqno, (curr_session->receiver->expected_seqno - RUDP_WINDOW)) &&
                SEQ_LT(rudpheader.seqno, curr_session->receiver->expected_seqno)) {
              uint32_t seqno = rudpheader.seqno + 1;
              rudp_packet *p = create_rudp_packet(RUDP_ACK, seqno, 0, NULL);
              send_packet(_true, (rudp_socket_t)file, p, &sender);
              free(p);
            }
          }
          else if(rudpheader.type == RUDP_FIN) {
            if(curr_session->receiver->status == OPEN) {
              if(rudpheader.seqno == curr_session->receiver->expected_seqno) {
                /* If the FIN is correct, we can ACK it */
                uint32_t seqno = curr_session->receiver->expected_seqno + 1;
                rudp_packet *p = create_rudp_packet(RUDP_ACK, seqno, 0, NULL);
                send_packet(_true, (rudp_socket_t)file, p, &sender);
                free(p);
                curr_session->receiver->session_finished = _true;

                if(curr_socket->close_requested) {
                  /* Can we close the socket now? */
                  session *head_sessions = curr_socket->sessions_list_head;
                  int all_done = true;
                  while(head_sessions != NULL) {
                    if(head_sessions->sender->session_finished == _false) {
                      all_done = false;
                    }
                    else if(head_sessions->receiver != NULL && head_sessions->receiver->session_finished == _false) {
                      all_done = _false;
                    }
                    else {
                      free(head_sessions->sender);
                      if(head_sessions->receiver) {
                        free(head_sessions->receiver);
                      }
                    }
                    
                    session *temp = head_sessions;
                    head_sessions = head_sessions->next;
                    free(temp);
                  }
                  if(all_done) {
                    if(curr_socket->handler != NULL) {
                      curr_socket->handler((rudp_socket_t)file, RUDP_EVENT_CLOSED, &sender);
                      event_fd_delete(receive_callback, (rudp_socket_t)file);
                      _close(file);
                      free(curr_socket);
                    }
                  }
                }
              }
              else {
                /* FIN received with incorrect sequence number - ignore it */
              }
            }
          }
        }
      }
    }
  }

  free(received_packet);
  return 0;
}

/* Close a RUDP socket */
int rudp_close(rudp_socket_t rsocket) {
  rudp_socket_list *curr_socket = socket_list_head;
  while(curr_socket->next != NULL) {
    if(curr_socket->rsock == rsocket) {
      break;
    }
    curr_socket = curr_socket->next;
  }
  if(curr_socket->rsock == rsocket) {
    curr_socket->close_requested = _true;        
    return 0;
  }
  
  return -1;
}

/* Register receive callback function */ 
int rudp_recvfrom_handler(rudp_socket_t rsocket, int (*handler)(rudp_socket_t, 
            struct sockaddr_in *, char *, int)) {

  if(handler == NULL) {
    fprintf(stderr, "rudp_recvfrom_handler failed: handler callback is null\n");
    return -1;
  }
  /* Find the proper socket from the socket list */
    rudp_socket_list *curr_socket = socket_list_head;
    while(curr_socket->next != NULL) {
      if(curr_socket->rsock == rsocket) {
        break;
      }
      curr_socket = curr_socket->next;
    }
    /* Extra check to handle the case where an invalid rsock is used */
    if(curr_socket->rsock == rsocket) {
      curr_socket->recv_handler = handler;
      return 0;
    }
  return -1;
}

/* Register event handler callback function with a RUDP socket */
int rudp_event_handler(rudp_socket_t rsocket, 
         int (*handler)(rudp_socket_t, rudp_event_t, 
            struct sockaddr_in *)) {

  if(handler == NULL) {
    fprintf(stderr, "rudp_event_handler failed: handler callback is null\n");
    return -1;
  }

  /* Find the proper socket from the socket list */
  rudp_socket_list *curr_socket = socket_list_head;
  while(curr_socket->next != NULL) {
    if(curr_socket->rsock == rsocket) {
      break;
    }
    curr_socket = curr_socket->next;
  }

  /* Extra check to handle the case where an invalid rsock is used */
  if(curr_socket->rsock == rsocket) {
    curr_socket->handler = handler;
    return 0;
  }
  return -1;
}


/* Sends a block of data to the receiver. Returns 0 on success, -1 on error */
int rudp_sendto(rudp_socket_t rsocket, void* data, int len, struct sockaddr_in* to) {

  if(len < 0 || len > RUDP_MAXPKTSIZE) {
    fprintf(stderr, "rudp_sendto Error: attempting to send with invalid max packet size\n");
    return -1;
  }

  if(rsocket < 0) {
    fprintf(stderr, "rudp_sendto Error: attempting to send on invalid socket\n");
    return -1;
  }

  if(to == NULL) {
    fprintf(stderr, "rudp_sendto Error: attempting to send to an invalid address\n");
    return -1;
  }

  bool_t new_session_created = _true;
  uint32_t seqno = 0;
  if(socket_list_head == NULL) {
    fprintf(stderr, "Error: attempt to send on invalid socket. No sockets in the list\n");
    return -1;
  }
  else {
    /* Find the correct socket in our list */
    rudp_socket_list *curr_socket = socket_list_head;
    while(curr_socket != NULL) {
      if(curr_socket->rsock == rsocket) {
        break;
      }
      curr_socket = curr_socket->next;
    }
    if(curr_socket->rsock == rsocket) {
      /* We found the correct socket, now see if a session already exists for this peer */
      net_data *data_item = (net_data *)malloc(sizeof(data));
      if(data_item == NULL) {
        fprintf(stderr, "rudp_sendto: Error allocating data queue\n");
        return -1;
      }  
      data_item->item = malloc(len);
      if(data_item->item == NULL) {
        fprintf(stderr, "rudp_sendto: Error allocating data queue item\n");
        return -1;
      }
      memcpy(data_item->item, data, len);
      data_item->len = len;
      data_item->next = NULL;

      if(curr_socket->sessions_list_head == NULL) {
        /* The list is empty, so we create a new sender session at the head of the list */
        seqno = rand();
        create_sender_session(curr_socket, seqno, to, &data_item);
      }
      else {
        bool_t session_found = _false;
        session *curr_session = curr_socket->sessions_list_head;
        session *last_in_list;
        while(curr_session != NULL) {
          if(compare_sockaddr(&curr_session->address, to) == 1) {
            bool_t data_is_queued = _false;
            bool_t we_must_queue = _true;

            if(curr_session->sender==NULL) {
              seqno = rand();
              create_sender_session(curr_socket, seqno, to, &data_item);
              rudp_packet *p = create_rudp_packet(RUDP_SYN, seqno, 0, NULL);            
              send_packet(_false, rsocket, p, to);
              free(p);
              new_session_created = _false ; /* Dont send the SYN twice */
              break;
            }

            if(curr_session->sender->data_queue != NULL)
              data_is_queued = _true;

            if(curr_session->sender->status == OPEN && !data_is_queued) {
              int i;
              for(i = 0; i < RUDP_WINDOW; i++) {
                if(curr_session->sender->sliding_window[i] == NULL) {
                  curr_session->sender->seqno = curr_session->sender->seqno + 1;
                  rudp_packet *datap = create_rudp_packet(RUDP_DATA, curr_session->sender->seqno, len, (char *)data);
                  curr_session->sender->sliding_window[i] = datap;
                  curr_session->sender->retransmission_attempts[i] = 0;
                  send_packet(_false, rsocket, datap, to);
                  we_must_queue = _false;
                  break;
                }
              }
            }

            if(we_must_queue == _true) {
              if(curr_session->sender->data_queue == NULL) {
                /* First entry in the data queue */
                curr_session->sender->data_queue = data_item;
              }
              else {
                /* Add to end of data queue */
                net_data *curr_socket = curr_session->sender->data_queue;
                while(curr_socket->next != NULL) {
                  curr_socket = curr_socket->next;
                }
                curr_socket->next = data_item;
              }
            }

            session_found = _true;
            new_session_created = _false;
            break;
          }
          if(curr_session->next == NULL)
            last_in_list=curr_session;

          curr_session = curr_session->next;
        }
        if(!session_found) {
          /* If not, create a new session */
          seqno = rand();
          create_sender_session(curr_socket, seqno, to, &data_item);
        }
      }
    }
    else {
      fprintf(stderr, "Error: attempt to send on invalid socket. Socket not found\n");
      return -1;
    }
  }
  if(new_session_created == _true) {
    /* Send the SYN for the new session */
    rudp_packet *p = create_rudp_packet(RUDP_SYN, seqno, 0, NULL);    
    send_packet(_false, rsocket, p, to);
    free(p);
  }
  return 0;
}

/* Callback function when a timeout occurs */
int timeout_callback(int fd, void *args) {
  timeoutargs *timeargs=(timeoutargs*)args;
  rudp_socket_list *curr_socket = socket_list_head;
  while(curr_socket != NULL) {
    if(curr_socket->rsock == timeargs->fd) {
      break;
    }
    curr_socket = curr_socket->next;
  }
  if(curr_socket->rsock == timeargs->fd) {
    bool_t session_found = _false;
      /* Check if we already have a session for this peer */
      session *curr_session = curr_socket->sessions_list_head;
      while(curr_session != NULL) {
        if(compare_sockaddr(&curr_session->address, timeargs->recipient) == 1) {
          /* Found an existing session */
          session_found = _true;
          break;
        }
        curr_session = curr_session->next;
      }
      if(session_found == _true) {
        if(timeargs->packet->header.type == RUDP_SYN) {
          if(curr_session->sender->syn_retransmit_attempts >= RUDP_MAXRETRANS) {
            curr_socket->handler(timeargs->fd, RUDP_EVENT_TIMEOUT, timeargs->recipient);
          }
          else {
            curr_session->sender->syn_retransmit_attempts++;
            send_packet(_false, timeargs->fd, timeargs->packet, timeargs->recipient);
            free(timeargs->packet);
          }
        }
        else if(timeargs->packet->header.type == RUDP_FIN) {
          if(curr_session->sender->fin_retransmit_attempts >= RUDP_MAXRETRANS) {
            curr_socket->handler(timeargs->fd, RUDP_EVENT_TIMEOUT, timeargs->recipient);
          }
          else {
            curr_session->sender->fin_retransmit_attempts++;
            send_packet(_false, timeargs->fd, timeargs->packet, timeargs->recipient);
            free(timeargs->packet);
          }
        }
        else {
          int i;
          int index;
          for(i = 0; i < RUDP_WINDOW; i++) {
            if(curr_session->sender->sliding_window[i] != NULL && 
               curr_session->sender->sliding_window[i]->header.seqno == timeargs->packet->header.seqno) {
              index = i;
            }
          }

          if(curr_session->sender->retransmission_attempts[index] >= RUDP_MAXRETRANS) {
            curr_socket->handler(timeargs->fd, RUDP_EVENT_TIMEOUT, timeargs->recipient);
          }
          else {
            curr_session->sender->retransmission_attempts[index]++;
            send_packet(_false, timeargs->fd, timeargs->packet, timeargs->recipient);
            free(timeargs->packet);
          }
        }
      }
    }

  free(timeargs->packet);
  free(timeargs->recipient);
  free(timeargs);
  return 0;
}

/* Transmit a packet via UDP */
int send_packet(bool_t is_ack, rudp_socket_t rsocket, rudp_packet *p, struct sockaddr_in *recipient) {
  char type[5];
  short t=p->header.type;
  if(t == 1)
    strcpy_s(type, "DATA");
  else if(t == 2)
    strcpy_s(type, "ACK");
  else if(t == 4)
    strcpy_s(type, "SYN");
  else if(t == 5)
    strcpy_s(type, "FIN");
  else
    strcpy_s(type, "BAD");

  printf("Sending %s packet to %s:%d seq number=%u on socket=%d\n",type, 
       inet_ntoa(recipient->sin_addr), ntohs(recipient->sin_port), p->header.seqno, (int)rsocket);

  if (DROP != 0 && rand() % DROP == 1) {
      printf("Dropped\n");
  }
  else {
    if (sendto((int)rsocket, (char *)p, sizeof(rudp_packet), 0, (sockaddr*)recipient, sizeof(struct sockaddr_in)) < 0) {
      fprintf(stderr, "rudp_sendto: sendto failed\n");
      return -1;
    }
  }

  if(!is_ack) {
    /* Set a timeout event if the packet isn't an ACK */
    timeoutargs *timeargs = (timeoutargs *)malloc(sizeof(timeoutargs));
    if(timeargs == NULL) {
      fprintf(stderr, "send_packet: Error allocating timeout args\n");
      return -1;
    }
    timeargs->packet = (rudp_packet *)malloc(sizeof(rudp_packet));
    if(timeargs->packet == NULL) {
      fprintf(stderr, "send_packet: Error allocating timeout args packet\n");
      return -1;
    }
    timeargs->recipient = (sockaddr_in *)malloc(sizeof(sockaddr_in));
    if(timeargs->packet == NULL) {
      fprintf(stderr, "send_packet: Error allocating timeout args recipient\n");
      return -1;
    }
    timeargs->fd = rsocket;
    memcpy(timeargs->packet, p, sizeof(rudp_packet));
    memcpy(timeargs->recipient, recipient, sizeof(sockaddr_in));  
  
    timeval currentTime;
    gettimeofday(&currentTime, NULL);
    timeval delay;
    delay.tv_sec = RUDP_TIMEOUT/1000;
    delay.tv_usec= 0;
    timeval timeout_time;
    timeradd(&currentTime, &delay, &timeout_time);

    rudp_socket_list *curr_socket = socket_list_head;
    while(curr_socket != NULL) {
      if(curr_socket->rsock == timeargs->fd) {
        break;
      }
      curr_socket = curr_socket->next;
    }
    if(curr_socket->rsock == timeargs->fd) {
      bool_t session_found = _false;
        /* Check if we already have a session for this peer */
        session *curr_session = curr_socket->sessions_list_head;
        while(curr_session != NULL) {
          if(compare_sockaddr(&curr_session->address, timeargs->recipient) == 1) {
            /* Found an existing session */
            session_found = _true;
            break;
          }
          curr_session = curr_session->next;
        }
        if(session_found) {
          if(timeargs->packet->header.type == RUDP_SYN) {
            curr_session->sender->syn_timeout_arg = timeargs;
          }
          else if(timeargs->packet->header.type == RUDP_FIN) {
            curr_session->sender->fin_timeout_arg = timeargs;
          }
          else if(timeargs->packet->header.type == RUDP_DATA) {
            int i;
            int index;
            for(i = 0; i < RUDP_WINDOW; i++) {
              if(curr_session->sender->sliding_window[i] != NULL && 
                 curr_session->sender->sliding_window[i]->header.seqno == timeargs->packet->header.seqno) {
                index = i;
              }
            }
            curr_session->sender->data_timeout_arg[index] = timeargs;
          }
        }
      }
      event_timeout(timeout_time, timeout_callback, timeargs, "timeout_callback");
  }
  return 0;
}

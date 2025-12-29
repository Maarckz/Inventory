/*
document.addEventListener('DOMContentLoaded', function() {
    // Configuração comum para os gráficos
    const chartOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                position: 'bottom',
                labels: {
                    padding: 20,
                    usePointStyle: true,
                    pointStyle: 'circle'
                }
            },
            tooltip: {
                callbacks: {
                    label: function(context) {
                        return `${context.label}: ${context.raw}`;
                    }
                }
            }
        },
        onClick: (event, elements, chart) => {
            if (elements.length > 0) {
                const index = elements[0].index;
                let query = '';
                
                switch(chart.canvas.id) {
                    case 'osChart':
                        query = 'inventory:os:' + chart.data.labels[index].toLowerCase();
                        break;
                    case 'cpuChart':
                        query = 'inventory:hardware:' + chart.data.labels[index].toLowerCase();
                        break;
                    //case 'ramChart':
                    //    const ramLabel = chart.data.labels[index].toLowerCase();
                    //    query = ramLabel.includes('+') 
                    //        ? 'ram_gb:>' + ramLabel.replace('+', '').replace('gb', '').trim()
                    //        : 'ram_gb:' + ramLabel;
                    //    break;


                    case 'ramChart':
                        const ramLabel = chart.data.labels[index].toLowerCase();
                        
                        query = 'ram_gb:' + ramLabel; 
                        break;
                            
                    case 'portChart':
                        const portLabel = chart.data.labels[index];
                        const portNumber = portLabel.replace(/\D/g, '');
                        if (portNumber) {
                            query = 'ports:' + portNumber;
                        } else {
                            query = 'ports:' + portLabel.toLowerCase();
                        }
                        break;
                    case 'processChart':
                        query = 'inventory:processes:' + chart.data.labels[index].toLowerCase();
                        break;
                    default:
                        query = chart.data.labels[index].toLowerCase();
                }
                
                window.location.href = `/search?query=${encodeURIComponent(query)}`;
            }
        }
    };

    // Carregar dados via AJAX
    fetch('/get_chart_data')
        .then(response => {
            if (!response.ok) {
                throw new Error('Erro ao carregar dados dos gráficos');
            }
            return response.json();
        })
        .then(data => {
            console.log('Dados recebidos:', data); // Para depuração
            
            // Verificar se os elementos dos gráficos existem
            const createChartIfExists = (id, creator) => {
                const element = document.getElementById(id);
                if (element) {
                    creator(element, data);
                } else {
                    console.warn(`Elemento #${id} não encontrado`);
                }
            };

            // Gráfico de Sistemas Operacionais
            createChartIfExists('osChart', (element) => {
                new Chart(element.getContext('2d'), {
                    type: 'doughnut',
                    data: {
                        labels: data.os_labels,
                        datasets: [{
                            data: data.os_data,
                            backgroundColor: [
                                '#6366F1', '#8B5CF6', '#0EA5E9', '#EC4899',
                                '#F43F5E', '#F97316', '#F59E0B'
                            ],
                            borderWidth: 0,
                            hoverOffset: 10
                        }]
                    },
                    options: chartOptions
                });
            });

            // Gráfico de Processadores
            createChartIfExists('cpuChart', (element) => {
                new Chart(element.getContext('2d'), {
                    type: 'bar',
                    data: {
                        labels: data.cpu_labels,
                        datasets: [{
                            label: 'Quantidade',
                            data: data.cpu_data,
                            backgroundColor: [
                                '#0EA5E9', '#8B5CF6', '#EC4899',
                                '#F43F5E', '#F97316', '#F59E0B',
                                '#10B981', '#3B82F6', '#EAB308',
                                '#A21CAF', '#BE185D', '#8B5CF6'
                            ],
                            borderRadius: 6,
                            borderWidth: 0
                        }]
                    },
                    options: {
                        ...chartOptions,
                        scales: {
                            y: {
                                beginAtZero: true,
                                grid: {
                                    drawBorder: false
                                },
                                ticks: {
                                    padding: 10
                                }
                            },
                            x: {
                                display: false,
                                grid: {
                                    display: false
                                }
                            }
                        },
                        plugins: {
                            legend: {
                                display: false
                            },
                            tooltip: {
                                callbacks: {
                                    title: function(context) {
                                        return data.cpu_labels[context[0].dataIndex];
                                    }
                                }
                            }
                        },
                        layout: {
                            padding: {
                                bottom: 10
                            }
                        }
                    }
                });
            });

            // Gráfico de Memória RAM
            createChartIfExists('ramChart', (element) => {
                new Chart(element.getContext('2d'), {
                    type: 'pie',
                    data: {
                        labels: data.ram_labels,
                        datasets: [{
                            data: data.ram_data,
                            backgroundColor: [
                                '#EC4899', '#0EA5E9', '#F97316', '#6366F1',
                                '#F43F5E', '#8B5CF6', '#F59E0B', '#10B981',
                                '#3B82F6', '#EAB308', '#A21CAF', '#BE185D',
                                '#22D3EE', '#F472B6', '#34D399', '#FBBF24'
                            ],
                            borderWidth: 0,
                            hoverOffset: 10
                        }]
                    },
                    options: chartOptions
                });
            });
// Gráfico de Portas de Rede
createChartIfExists('portChart', (element) => {
    new Chart(element.getContext('2d'), {
        type: 'bar',
        data: {
            labels: data.port_labels,
            datasets: [{
                label: 'Ocorrências',
                data: data.port_data,
                backgroundColor: data.port_labels.map((label, index) => {
                    return data.port_protocols[index] === 'tcp' ? '#3B82F6' : '#10B981';
                }),
                borderRadius: 6,
                borderWidth: 0
            }]
        },
        options: {
            ...chartOptions,
            indexAxis: 'y',
            plugins: {
                legend: {
                    display: false // Removendo a legenda
                },
                tooltip: {
                    callbacks: {
                        title: function(tooltipItems) {
                            const label = data.port_labels[tooltipItems[0].dataIndex];
                            const portMatch = label.match(/(\d+)\/(TCP|UDP)/);
                            return portMatch ? `Porta ${portMatch[1]}` : label;
                        },
                        afterBody: function(tooltipItems) {
                            const label = data.port_labels[tooltipItems[0].dataIndex];
                            return [label.replace(' - ', ': ')];
                        },
                        labelColor: function(context) {
                            return {
                                borderColor: 'transparent',
                                backgroundColor: context.dataset.backgroundColor[context.dataIndex],
                                borderRadius: 2
                            };
                        }
                    }
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    grid: {
                        drawBorder: false
                    }
                }
            }
        }
    });
});
            // Gráfico de Processos em Execução
            createChartIfExists('processChart', (element) => {
                new Chart(element.getContext('2d'), {
                    type: 'bar',
                    data: {
                        labels: data.process_labels,
                        datasets: [{
                            label: 'Ocorrências',
                            data: data.process_data,
                            backgroundColor: '#8B5CF6',
                            borderRadius: 6,
                            borderWidth: 0
                        }]
                    },
                    options: {
                        ...chartOptions,
                        indexAxis: 'y',
                        plugins: {
                            legend: {
                                display: false
                            }
                        },
                        scales: {
                            x: {
                                beginAtZero: true,
                                grid: {
                                    drawBorder: false
                                }
                            }
                        }
                    }
                });
            });
        })
        .catch(error => {
            console.error('Erro ao carregar dados dos gráficos:', error);
            // Você pode adicionar aqui uma mensagem de erro para o usuário
        });
});
*/